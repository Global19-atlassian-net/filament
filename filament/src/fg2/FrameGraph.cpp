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
#include "fg2/details/DependencyGraph.h"

#include "details/Engine.h"

#include <backend/DriverEnums.h>
#include <backend/Handle.h>

#include <utils/Panic.h>

namespace filament::fg2 {

FrameGraph::Builder::Builder(FrameGraph& fg, PassNode* passNode) noexcept
        : mFrameGraph(fg), mPassNode(passNode) {
}

FrameGraph::Builder::~Builder() noexcept = default;

void FrameGraph::Builder::sideEffect() noexcept {
    mPassNode->makeTarget();
}

const char* FrameGraph::Builder::getName(FrameGraphHandle handle) const noexcept {
    return mFrameGraph.getResource(handle)->name;
}

RenderPass FrameGraph::Builder::declareRenderPass(const char* name,
        RenderPass::Descriptor const& desc) {
    // it's safe here to cast to RenderPassNode because we can't be here for a PresentPassNode
    // also only RenderPassNodes have the concept of render targets.
    return static_cast<RenderPassNode*>(mPassNode)->declareRenderTarget(mFrameGraph, *this, name, desc);
}

FrameGraphId<Texture> FrameGraph::Builder::declareRenderPass(FrameGraphId<Texture> color, uint32_t* index) {
    auto[attachments, id] = declareRenderPass(getName(color),
            { .attachments = { .color = { color }}});
    if (index) *index = id;
    return attachments.color[0];
}

// ------------------------------------------------------------------------------------------------

FrameGraph::FrameGraph(ResourceAllocatorInterface& resourceAllocator)
        : mResourceAllocator(resourceAllocator),
          mArena("FrameGraph Arena", 131072),
          mResourceSlots(mArena),
          mResources(mArena),
          mResourceNodes(mArena),
          mPassNodes(mArena)
{
    mResourceSlots.reserve(256);
    mResources.reserve(256);
    mResourceNodes.reserve(256);
    mPassNodes.reserve(64);
}

FrameGraph::~FrameGraph() = default;

void FrameGraph::reset() noexcept {
    // the order of destruction is important here
    mPassNodes.clear();
    mResourceNodes.clear();
    mResources.clear();
    mResourceSlots.clear();
}

FrameGraph& FrameGraph::compile() noexcept {
    DependencyGraph& dependencyGraph = mGraph;

    // first we cull unreachable nodes
    dependencyGraph.cull();

    /*
     * update the reference counter of the resource themselves and
     * compute first/last users for active passes
     */

    for (auto& pPassNode : mPassNodes) {
        if (pPassNode->isCulled()) {
            continue;
        }

        auto const& reads = dependencyGraph.getIncomingEdges(pPassNode.get());
        for (auto const& edge : reads) {
            // all incoming edges should be valid by construction
            assert(dependencyGraph.isEdgeValid(edge));
            auto pNode = static_cast<ResourceNode*>(dependencyGraph.getNode(edge->from));
            VirtualResource* pResource = getResource(pNode->resourceHandle);
            pResource->neededByPass(pPassNode.get());
        }

        auto const& writes = dependencyGraph.getOutgoingEdges(pPassNode.get());
        for (auto const& edge : writes) {
            // an outgoing edge might be invalid if the node it points to has been culled
            // but, because we are not culled and we're a pass, we add a reference to
            // the resource we are writing to.
            auto pNode = static_cast<ResourceNode*>(dependencyGraph.getNode(edge->to));
            VirtualResource* pResource = getResource(pNode->resourceHandle);
            pResource->neededByPass(pPassNode.get());
        }

        pPassNode->resolve();
    }

    /*
     * Resolve Usage bits
     */
    for (auto& pNode : mResourceNodes) {
        pNode->resolveResourceUsage(dependencyGraph);
    }

    return *this;
}

void FrameGraph::execute(backend::DriverApi& driver) noexcept {
    auto const& passNodes = mPassNodes;
    auto const& resourcesList = mResources;
    auto& resourceAllocator = mResourceAllocator;

    driver.pushGroupMarker("FrameGraph");
    for (auto const& node : passNodes) {
        if (!node->isCulled()) {
            driver.pushGroupMarker(node->getName());

            // devirtualize resourcesList
            for (auto& pResource : resourcesList) {
                if (pResource->first == node.get()) {
                    pResource->devirtualize(resourceAllocator);
                }
            }

            // call execute
            FrameGraphResources resources(*this, *node);
            node->execute(resources, driver);

            // destroy resourcesList
            for (auto& pResource : resourcesList) {
                if (pResource->last == node.get()) {
                    pResource->destroy(resourceAllocator);
                }
            }

            driver.popGroupMarker();
        }
    }
    // this is a good place to kick the GPU, since we've just done a bunch of work
    driver.flush();
    driver.popGroupMarker();
}

void FrameGraph::addPresentPass(std::function<void(FrameGraph::Builder&)> setup) noexcept {
    PresentPassNode* node = mArena.make<PresentPassNode>(*this);
    mPassNodes.emplace_back(node, mArena);
    Builder builder(*this, node);
    setup(builder);
    builder.sideEffect();
}

FrameGraph::Builder FrameGraph::addPassInternal(char const* name, PassBase* base) noexcept {
    // record in our pass list and create the builder
    PassNode* node = mArena.make<RenderPassNode>(*this, name, base);
    base->setNode(node);
    mPassNodes.emplace_back(node, mArena);
    return Builder(*this, node);
}

FrameGraphHandle FrameGraph::createNewVersion(FrameGraphHandle handle, FrameGraphHandle parent) noexcept {
    ResourceSlot& slot = getResourceSlot(handle);
    mResources[slot.rid]->version = ++handle.version;   // increase the parent's version
    slot.nid = mResourceNodes.size();   // create the new parent node
    ResourceNode* newNode = mArena.make<ResourceNode>(*this, handle, parent);
    mResourceNodes.emplace_back(newNode, mArena);
    return handle;
}

FrameGraphHandle FrameGraph::createNewVersionForSubresourceIfNeeded(FrameGraphHandle handle) noexcept {
    ResourceSlot& slot = getResourceSlot(handle);
    if (slot.sid < 0) {
        // if we don't already have a new ResourceNode for this resource, create one.
        // we keep the old ResourceNode index so we can direct all the reads to it.
        slot.sid = slot.nid; // record the current ResourceNode of the parent
        handle = createNewVersion(handle, FrameGraphHandle{});
    }
    return handle;
}

FrameGraphHandle FrameGraph::addResourceInternal(UniquePtr<VirtualResource> resource) noexcept {
    return addSubResourceInternal(FrameGraphHandle{}, std::move(resource));
}

FrameGraphHandle FrameGraph::addSubResourceInternal(FrameGraphHandle parent,
        UniquePtr<VirtualResource> resource) noexcept {
    FrameGraphHandle handle(mResourceSlots.size());
    ResourceSlot& slot = mResourceSlots.emplace_back();
    slot.rid = mResources.size();
    slot.nid = mResourceNodes.size();
    mResources.push_back(std::move(resource));
    ResourceNode* pNode = mArena.make<ResourceNode>(*this, handle, parent);
    mResourceNodes.emplace_back(pNode, mArena);
    return handle;
}

FrameGraphHandle FrameGraph::readInternal(FrameGraphHandle handle, PassNode* passNode,
        std::function<bool(ResourceNode*, VirtualResource*)> connect) {

    if (!assertValid(handle)) {
        return {};
    }

    VirtualResource* const resource = getResource(handle);
    ResourceNode* const node = getResourceNode(handle);

    // Check preconditions
    bool passAlreadyAWriter = node->hasWriteFrom(passNode);
    if (!ASSERT_PRECONDITION_NON_FATAL(!passAlreadyAWriter,
            "Pass \"%s\" already writes to \"%s\"",
            passNode->getName(), node->getName())) {
        return {};
    }

    // Connect can fail if usage flags are incorrectly used
    if (connect(node, resource)) {
        if (resource->isSubResource()) {
            auto* sinkParentNode = node->getParentNode();
            ResourceSlot& slot = getResourceSlot(sinkParentNode->resourceHandle);
            ResourceNode* readParentNode = mResourceNodes[slot.sid].get();
            node->setParentReadDependency(readParentNode);
        }

        // if a resource has a subresource, then its handle becomes valid again as soon as it's used.
        ResourceSlot& slot = getResourceSlot(handle);
        if (slot.sid >= 0) {
            handle.version = resource->version;
// This might be needed
//            slot.sid = slot.nid; // record the current ResourceNode of the parent
//            handle = createNewVersion(handle, FrameGraphHandle{});
        }

        return handle;
    }

    return {};
}

FrameGraphHandle FrameGraph::writeInternal(FrameGraphHandle handle, PassNode* passNode,
        std::function<bool(ResourceNode*, VirtualResource*)> connect) {
    if (!assertValid(handle)) {
        return {};
    }

    VirtualResource* const resource = getResource(handle);
    ResourceNode* node = getResourceNode(handle);
    ResourceNode* const parentNode = node->getParentNode();

    // if this node already writes to this resource, just update the used bits
    if (!node->hasWriteFrom(passNode)) {
        // if we don't already have a writer, it just means the resource was just created
        // and was never written to, so we don't need a new node or increase the version number
        if (node->hasWriter()) {
            handle = createNewVersion(handle,
                    parentNode ? parentNode->resourceHandle : FrameGraphHandle{});
            // refresh the node
            node = getResourceNode(handle);
        }
    }

    if (connect(node, resource)) {
        if (resource->isSubResource()) {
            node->setParentWriteDependency(parentNode);
        }
        if (resource->isImported()) {
            // writing to an imported resource implies a side-effect
            passNode->makeTarget();
        }
        return handle;
    } else {
        // FIXME: we need to undo everything we did to this point
    }

    return {};
}

FrameGraphId<Texture> FrameGraph::import(char const* name, RenderPass::Descriptor const& desc,
        backend::Handle<backend::HwRenderTarget> target) {
    UniquePtr<VirtualResource> vresource(
            mArena.make<ImportedRenderTarget>(name,Texture::Descriptor{
                            .width = desc.viewport.width,
                            .height = desc.viewport.height,
                    }, desc, target), mArena);
    return FrameGraphId<Texture>(addResourceInternal(std::move(vresource)));
}

bool FrameGraph::isValid(FrameGraphHandle handle) const {
    // Code below is written this way so we can set breakpoints easily.
    if (!handle.isInitialized()) {
        return false;
    }

    VirtualResource const* const pResource = getResource(handle);
    if (handle.version != pResource->version) {
        // if this resource has some subresources, then it's possible for a handle to be
        // ine version behind until it is used -- which is probably what is happening right now.
        ResourceSlot slot = getResourceSlot(handle);
        if (slot.sid >= 0) {
            if (handle.version + 1 == pResource->version) {
                return true;
            }
        }
        return false;
    }
    return true;
}

bool FrameGraph::assertValid(FrameGraphHandle handle) const {
    return ASSERT_PRECONDITION_NON_FATAL(isValid(handle),
            "Resource handle is invalid or uninitialized {id=%u, version=%u}",
            (int)handle.index, (int)handle.version);
}

bool FrameGraph::isCulled(PassBase const& pass) const noexcept {
    return pass.getNode().isCulled();
}

bool FrameGraph::isAcyclic() const noexcept {
    return mGraph.isAcyclic();
}

void FrameGraph::export_graphviz(utils::io::ostream& out, char const* name) {
    mGraph.export_graphviz(out, name);
}

// ------------------------------------------------------------------------------------------------

/*
 * Explicit template instantiation for for Texture which is a known type,
 * to reduce compile time and code size.
 */

template void FrameGraph::present(FrameGraphId<Texture> input);

template FrameGraphId<Texture> FrameGraph::create(char const* name,
        Texture::Descriptor const& desc) noexcept;

template FrameGraphId<Texture> FrameGraph::createSubresource(FrameGraphId<Texture> parent,
        char const* name, Texture::SubResourceDescriptor const& desc) noexcept;

template FrameGraphId<Texture> FrameGraph::import(char const* name,
        Texture::Descriptor const& desc, Texture::Usage usage, Texture const& resource) noexcept;

template FrameGraphId<Texture> FrameGraph::read(PassNode* passNode,
        FrameGraphId<Texture> input, Texture::Usage usage);

template FrameGraphId<Texture> FrameGraph::write(PassNode* passNode,
        FrameGraphId<Texture> input, Texture::Usage usage);

} // namespace filament::fg2
