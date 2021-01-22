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
#include "fg2/FrameGraphResources.h"
#include "fg2/details/PassNode.h"

namespace filament::fg2 {

FrameGraphResources::FrameGraphResources(FrameGraph& fg, PassNode& passNode) noexcept
    : mFrameGraph(fg), mPassNode(passNode) {
}

const char* FrameGraphResources::getPassName() const noexcept {
    return mPassNode.getName();
}

VirtualResource const* FrameGraphResources::getResource(FrameGraphHandle handle) const noexcept {
    return mFrameGraph.getResource(handle);
}

FrameGraphResources::RenderPassInfo FrameGraphResources::getRenderPassInfo(
        uint32_t id) const noexcept {
    // this cast is safe because this can only be called from a RenderPassNode
    RenderPassNode const& renderPassNode = static_cast<RenderPassNode const&>(mPassNode);
    RenderPassNode::RenderTargetData const& rt = renderPassNode.getRenderTargetData(id);
    return { rt.backend.target, rt.backend.params };
}

} // namespace filament::fg2


