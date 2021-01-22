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

#ifndef TNT_FILAMENT_FG2_RESOURCENODE_H
#define TNT_FILAMENT_FG2_RESOURCENODE_H

#include "fg2/details/DependencyGraph.h"
#include "fg2/details/Utilities.h"

namespace utils {
class CString;
} // namespace utils

namespace filament::fg2 {

class FrameGraph;
class ResourceEdgeBase;

class ResourceNode : public DependencyGraph::Node {
public:
    ResourceNode(FrameGraph& fg, FrameGraphHandle h, FrameGraphHandle parent) noexcept;
    ~ResourceNode() noexcept override;

    ResourceNode(ResourceNode const&) = delete;
    ResourceNode& operator=(ResourceNode const&) = delete;

    void addOutgoingEdge(ResourceEdgeBase* edge) noexcept;
    void setIncomingEdge(ResourceEdgeBase* edge) noexcept;

    // constants
    const FrameGraphHandle resourceHandle;

    bool hasWriter() const noexcept {
        return mWriter != nullptr;
    }

    bool hasReaders() const noexcept {
        return !mReaders.empty();
    }

    bool hasActiveReaders() const noexcept;

    ResourceEdgeBase* getReaderEdgeForPass(PassNode const* node) const noexcept;

    ResourceEdgeBase* getWriterEdgeForPass(PassNode const* node) const noexcept;

    bool hasWriteFrom(PassNode const* node) const noexcept;

    void resolveResourceUsage(DependencyGraph& graph) noexcept;

    ResourceNode* getParentNode() noexcept;

    void setParentReadDependency(ResourceNode* parent) noexcept;
    void setParentWriteDependency(ResourceNode* parent) noexcept;

    // virtuals from DependencyGraph::Node
    char const* getName() const noexcept override;

private:
    FrameGraph& mFrameGraph;
    std::vector<ResourceEdgeBase *> mReaders;
    ResourceEdgeBase* mWriter = nullptr;
    FrameGraphHandle mParentHandle;
    DependencyGraph::Edge* mParendReadEdge = nullptr;
    DependencyGraph::Edge* mParendWriteEdge = nullptr;

    // virtuals from DependencyGraph::Node
    void onCulled(DependencyGraph* graph) noexcept override;
    utils::CString graphvizify() const noexcept override;
    utils::CString graphvizifyEdgeColor() const noexcept override;
};

} // namespace filament::fg2

#endif //TNT_FILAMENT_FG2_RESOURCENODE_H
