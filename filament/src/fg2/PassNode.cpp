/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fg2/FrameGraph.h"
#include "fg2/details/PassNode.h"
#include "fg2/details/ResourceNode.h"
#include "ResourceAllocator.h"

#include <details/Texture.h>

#include <string>

namespace filament::fg2 {

PassNode::PassNode(FrameGraph& fg) noexcept
        : DependencyGraph::Node(fg.getGraph()) {
}

PassNode::PassNode(PassNode&& rhs) noexcept = default;

PassNode::~PassNode() noexcept = default;

utils::CString PassNode::graphvizifyEdgeColor() const noexcept {
    return utils::CString{"red"};
}

// ------------------------------------------------------------------------------------------------

RenderPassNode::RenderPassNode(FrameGraph& fg, const char* name, PassBase* base) noexcept
        : PassNode(fg), mFrameGraph(fg), mName(name), mPassBase(base, fg.getArena()) {
}
RenderPassNode::RenderPassNode(RenderPassNode&& rhs) noexcept = default;
RenderPassNode::~RenderPassNode() noexcept = default;

void RenderPassNode::onCulled(DependencyGraph* graph) noexcept {
}

void RenderPassNode::execute(FrameGraphResources const& resources,
        backend::DriverApi& driver) noexcept {

    FrameGraph& fg = mFrameGraph;
    ResourceAllocatorInterface& resourceAllocator = fg.getResourceAllocator();

    // create the render targets
    for (auto& rt : mRenderTargetData) {
        rt.devirtualize(fg, resourceAllocator);
    }

    mPassBase->execute(resources, driver);
    
    // destroy the render targets
    for (auto& rt : mRenderTargetData) {
        rt.destroy(resourceAllocator);
    }
}

RenderPass RenderPassNode::declareRenderTarget(FrameGraph& fg, FrameGraph::Builder& builder,
        const char* name, RenderPass::Descriptor const& descriptor) {

    RenderTargetData data;
    data.name = name;
    data.descriptor = descriptor;
    RenderPass::Attachments& attachments = data.descriptor.attachments;

    const Texture::Usage usages[6] = {
            Texture::Usage::COLOR_ATTACHMENT,
            Texture::Usage::COLOR_ATTACHMENT,
            Texture::Usage::COLOR_ATTACHMENT,
            Texture::Usage::COLOR_ATTACHMENT,
            Texture::Usage::DEPTH_ATTACHMENT,
            Texture::Usage::STENCIL_ATTACHMENT
    };

    // retrieve the ResourceNode of the attachments coming to us -- this will be used later
    // to compute the discard flags.
    for (size_t i = 0; i < 6; i++) {
        if (descriptor.attachments.array[i].isInitialized()) {
            data.incoming[i] = fg.getResourceNode(attachments.array[i]);
            attachments.array[i] = builder.write(attachments.array[i], usages[i]);
            data.outgoing[i] = fg.getResourceNode(attachments.array[i]);
            data.attachmentInfo[i] = attachments.array[i];
            // if the outgoing node is the same than the incoming node, it means we in fact
            // didn't have a incoming node (the node was created but not used yet).
            if (data.outgoing[i] == data.incoming[i]) {
                data.incoming[i] = nullptr;
            }
        }
    }

    // Handle our special imported render target
    if (attachments.color[0].isInitialized()) {
        VirtualResource* pResource = fg.getResource(attachments.color[0]);
        ImportedRenderTarget* pImportedRenderTarget = pResource->asImportedRenderTarget();
        if (pImportedRenderTarget) {
            data.imported = true;
            data.descriptor = pImportedRenderTarget->rtdesc;
            data.backend.target = pImportedRenderTarget->target;
        }
    }

    uint32_t id = mRenderTargetData.size();
    mRenderTargetData.push_back(data);
    return { data.descriptor.attachments, id };
}

void RenderPassNode::resolve() noexcept {
    using namespace backend;

    const backend::TargetBufferFlags flags[6] = {
            TargetBufferFlags::COLOR0,
            TargetBufferFlags::COLOR1,
            TargetBufferFlags::COLOR2,
            TargetBufferFlags::COLOR3,
            TargetBufferFlags::DEPTH,
            TargetBufferFlags::STENCIL
    };

    for (auto& rt : mRenderTargetData) {

        uint32_t minWidth = std::numeric_limits<uint32_t>::max();
        uint32_t minHeight = std::numeric_limits<uint32_t>::max();
        uint32_t maxWidth = 0;
        uint32_t maxHeight = 0;

        /*
         * Compute discard flags
         */
        for (size_t i = 0; i < 6; i++) {
            // we use 'outgoing' has a proxy for 'do we have an attachment here?'
            if (rt.outgoing[i]) {
                assert(rt.descriptor.attachments.array[i].isInitialized());

                rt.targetBufferFlags |= flags[i];

                // start by discarding all the attachments we have
                // (we could set to ALL, but this is cleaner)
                rt.backend.params.flags.discardStart |= flags[i];
                rt.backend.params.flags.discardEnd   |= flags[i];
                if (rt.outgoing[i]->hasActiveReaders()) {
                    rt.backend.params.flags.discardEnd &= ~flags[i];
                }
                if (rt.incoming[i] && rt.incoming[i]->hasWriter()) {
                    rt.backend.params.flags.discardStart &= ~flags[i];
                }

                VirtualResource* pResource = mFrameGraph.getResource(rt.descriptor.attachments.array[i]);
                Resource<Texture>* pTextureResource = static_cast<Resource<Texture>*>(pResource);

                // update attachment sample count if not specified and usage permits it
                if (!rt.descriptor.samples &&
                    none(pTextureResource->usage & backend::TextureUsage::SAMPLEABLE)) {
                    pTextureResource->descriptor.samples = rt.descriptor.samples;
                }

                // figure out the min/max dimensions across all attachments
                const size_t level = pTextureResource->subResourceDescriptor.level;
                const uint32_t w = FTexture::valueForLevel(level, pTextureResource->descriptor.width);
                const uint32_t h = FTexture::valueForLevel(level, pTextureResource->descriptor.height);
                minWidth = std::min(minWidth, w);
                maxWidth = std::max(maxWidth, w);
                minHeight = std::min(minHeight, h);
                maxHeight = std::max(maxHeight, h);
            }
            // additionally, clear implies discardStart
            rt.backend.params.flags.discardStart |= (
                    rt.descriptor.clearFlags & rt.targetBufferFlags);
        }

        assert(any(rt.targetBufferFlags));

        // of all attachments size matches there are no ambiguity about the RT size.
        // if they don't match however, we select a size that will accommodate all attachments.
        uint32_t width = maxWidth;
        uint32_t height = maxHeight;

        // Update the descriptor if no size was specified (auto mode)
        if (!rt.descriptor.viewport.width) {
            rt.descriptor.viewport.width = width;
        }
        if (!rt.descriptor.viewport.height) {
            rt.descriptor.viewport.height = height;
        }

        rt.backend.params.clearColor = rt.descriptor.clearColor;
        rt.backend.params.flags.clear = (rt.descriptor.clearFlags & rt.targetBufferFlags);
        rt.backend.params.viewport = rt.descriptor.viewport;
        rt.descriptor.samples = rt.descriptor.samples;
    }
}

void RenderPassNode::RenderTargetData::devirtualize(FrameGraph& fg,
        ResourceAllocatorInterface& resourceAllocator) noexcept {
    assert(any(targetBufferFlags));
    if (UTILS_LIKELY(!imported)) {

        backend::TargetBufferInfo info[6] = {};
        for (size_t i = 0; i < 6; i++) {
            if (attachmentInfo[i].isInitialized()) {
                auto const* pResource = static_cast<Resource<Texture> const*>(
                        fg.getResource(attachmentInfo[i]));
                info[i].handle = pResource->resource.handle;
                info[i].level = pResource->subResourceDescriptor.level;
                info[i].layer = pResource->subResourceDescriptor.layer;
            }
        }

        backend.target = resourceAllocator.createRenderTarget(
                name, targetBufferFlags,
                backend.params.viewport.width,
                backend.params.viewport.height,
                descriptor.samples,
                { info[0], info[1], info[2], info[3] },
                info[4], info[5]);
    }
}

void RenderPassNode::RenderTargetData::destroy(
        ResourceAllocatorInterface& resourceAllocator) noexcept {
    if (UTILS_LIKELY(!imported)) {
        resourceAllocator.destroyRenderTarget(backend.target);
    }
}

RenderPassNode::RenderTargetData const& RenderPassNode::getRenderTargetData(
        uint32_t id) const noexcept {
    assert(id < mRenderTargetData.size());
    return mRenderTargetData[id];
}

utils::CString RenderPassNode::graphvizify() const noexcept {
    std::string s;

    uint32_t id = getId();
    const char* const nodeName = getName();
    uint32_t refCount = getRefCount();

    s.append("[label=\"");
    s.append(nodeName);
    s.append("\\nrefs: ");
    s.append(std::to_string(refCount));
    s.append(", id: ");
    s.append(std::to_string(id));

    for (auto const& rt :mRenderTargetData) {
        s.append("\\nS:");
        s.append(utils::to_string(rt.backend.params.flags.discardStart).c_str());
        s.append(", E:");
        s.append(utils::to_string(rt.backend.params.flags.discardEnd).c_str());
    }

    s.append("\", ");

    s.append("style=filled, fillcolor=");
    s.append(refCount ? "darkorange" : "darkorange4");
    s.append("]");

    return utils::CString{ s.c_str() };
}

// ------------------------------------------------------------------------------------------------

PresentPassNode::PresentPassNode(FrameGraph& fg) noexcept
        : PassNode(fg) {
}
PresentPassNode::PresentPassNode(PresentPassNode&& rhs) noexcept = default;
PresentPassNode::~PresentPassNode() noexcept = default;

char const* PresentPassNode::getName() const noexcept {
    return "Present";
}

void PresentPassNode::onCulled(DependencyGraph* graph) noexcept {
}

utils::CString PresentPassNode::graphvizify() const noexcept {
    std::string s;
    s.reserve(128);
    uint32_t id = getId();
    s.append("[label=\"Present , id: ");
    s.append(std::to_string(id));
    s.append("\", style=filled, fillcolor=red3]");
    s.shrink_to_fit();
    return utils::CString{ s.c_str() };
}

void PresentPassNode::execute(FrameGraphResources const&, backend::DriverApi&) noexcept {
}

void PresentPassNode::resolve() noexcept {
}

} // namespace filament::fg2
