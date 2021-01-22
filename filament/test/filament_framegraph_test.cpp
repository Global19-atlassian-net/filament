/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "ResourceAllocator.h"

#include <backend/Platform.h>

#include "private/backend/CommandStream.h"

#include "fg2/FrameGraph.h"
#include "fg2/FrameGraphResources.h"
#include "fg2/details/DependencyGraph.h"

using namespace filament;
using namespace backend;
using namespace fg2;

class MockResourceAllocator : public ResourceAllocatorInterface {
    uint32_t handle = 0;
public:
    backend::RenderTargetHandle createRenderTarget(const char* name,
            backend::TargetBufferFlags targetBufferFlags,
            uint32_t width,
            uint32_t height,
            uint8_t samples,
            backend::MRT color,
            backend::TargetBufferInfo depth,
            backend::TargetBufferInfo stencil) noexcept override {
        return backend::RenderTargetHandle(++handle);
    }

    void destroyRenderTarget(backend::RenderTargetHandle h) noexcept override {
    }

    backend::TextureHandle createTexture(const char* name, backend::SamplerType target,
            uint8_t levels,
            backend::TextureFormat format, uint8_t samples, uint32_t width, uint32_t height,
            uint32_t depth, backend::TextureUsage usage) noexcept override {
        return backend::TextureHandle(++handle);
    }

    void destroyTexture(backend::TextureHandle h) noexcept override {
    }
};

class FrameGraphTest : public testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
        //fg.export_graphviz(utils::slog.d);
    }

    Backend backend = Backend::NOOP;
    CircularBuffer buffer = CircularBuffer{ 8192 };
    DefaultPlatform* platform = DefaultPlatform::create(&backend);
    CommandStream driverApi = CommandStream{ *platform->createDriver(nullptr), buffer };
    MockResourceAllocator resourceAllocator;
    FrameGraph fg{resourceAllocator};
};

class Node : public DependencyGraph::Node {
    const char *mName;
    bool mCulledCalled = false;
    char const* getName() const noexcept override { return mName; }
    void onCulled(DependencyGraph* graph) noexcept override { mCulledCalled = true; }
public:
    Node(DependencyGraph& graph, const char* name) noexcept : DependencyGraph::Node(graph), mName(name) { }
    bool isCulledCalled() const noexcept { return mCulledCalled; }
};

TEST(DependencyGraphTest, Simple) {
    DependencyGraph graph;
    Node* n0 = new Node(graph, "node 0");
    Node* n1 = new Node(graph, "node 1");
    Node* n2 = new Node(graph, "node 2");

    new DependencyGraph::Edge(graph, n0, n1);
    new DependencyGraph::Edge(graph, n1, n2);
    n2->makeTarget();

    graph.cull();

    //graph.export_graphviz(utils::slog.d);

    EXPECT_FALSE(n2->isCulled());
    EXPECT_FALSE(n1->isCulled());
    EXPECT_FALSE(n0->isCulled());
    EXPECT_FALSE(n2->isCulledCalled());
    EXPECT_FALSE(n1->isCulledCalled());
    EXPECT_FALSE(n0->isCulledCalled());

    EXPECT_EQ(n0->getRefCount(), 1);
    EXPECT_EQ(n1->getRefCount(), 1);
    EXPECT_EQ(n2->getRefCount(), 1);

    auto edges = graph.getEdges();
    auto nodes = graph.getNodes();
    graph.clear();
    for (auto e : edges) { delete e; }
    for (auto n : nodes) { delete n; }
}

TEST(DependencyGraphTest, Culling1) {
    DependencyGraph graph;
    Node* n0 = new Node(graph, "node 0");
    Node* n1 = new Node(graph, "node 1");
    Node* n2 = new Node(graph, "node 2");
    Node* n1_0 = new Node(graph, "node 1.0");

    new DependencyGraph::Edge(graph, n0, n1);
    new DependencyGraph::Edge(graph, n1, n2);
    new DependencyGraph::Edge(graph, n1, n1_0);
    n2->makeTarget();

    graph.cull();

    //graph.export_graphviz(utils::slog.d);

    EXPECT_TRUE(n1_0->isCulled());
    EXPECT_TRUE(n1_0->isCulledCalled());

    EXPECT_FALSE(n2->isCulled());
    EXPECT_FALSE(n1->isCulled());
    EXPECT_FALSE(n0->isCulled());
    EXPECT_FALSE(n2->isCulledCalled());
    EXPECT_FALSE(n1->isCulledCalled());
    EXPECT_FALSE(n0->isCulledCalled());

    EXPECT_EQ(n0->getRefCount(), 1);
    EXPECT_EQ(n1->getRefCount(), 1);
    EXPECT_EQ(n2->getRefCount(), 1);

    auto edges = graph.getEdges();
    auto nodes = graph.getNodes();
    graph.clear();
    for (auto e : edges) { delete e; }
    for (auto n : nodes) { delete n; }
}

TEST(DependencyGraphTest, Culling2) {
    DependencyGraph graph;
    Node* n0 = new Node(graph, "node 0");
    Node* n1 = new Node(graph, "node 1");
    Node* n2 = new Node(graph, "node 2");
    Node* n1_0 = new Node(graph, "node 1.0");
    Node* n1_0_0 = new Node(graph, "node 1.0.0");
    Node* n1_0_1 = new Node(graph, "node 1.0.0");

    new DependencyGraph::Edge(graph, n0, n1);
    new DependencyGraph::Edge(graph, n1, n2);
    new DependencyGraph::Edge(graph, n1, n1_0);
    new DependencyGraph::Edge(graph, n1_0, n1_0_0);
    new DependencyGraph::Edge(graph, n1_0, n1_0_1);
    n2->makeTarget();

    graph.cull();

    //graph.export_graphviz(utils::slog.d);

    EXPECT_TRUE(n1_0->isCulled());
    EXPECT_TRUE(n1_0_0->isCulled());
    EXPECT_TRUE(n1_0_1->isCulled());
    EXPECT_TRUE(n1_0->isCulledCalled());
    EXPECT_TRUE(n1_0_0->isCulledCalled());
    EXPECT_TRUE(n1_0_1->isCulledCalled());

    EXPECT_FALSE(n2->isCulled());
    EXPECT_FALSE(n1->isCulled());
    EXPECT_FALSE(n0->isCulled());
    EXPECT_FALSE(n2->isCulledCalled());
    EXPECT_FALSE(n1->isCulledCalled());
    EXPECT_FALSE(n0->isCulledCalled());

    EXPECT_EQ(n0->getRefCount(), 1);
    EXPECT_EQ(n1->getRefCount(), 1);
    EXPECT_EQ(n2->getRefCount(), 1);

    auto edges = graph.getEdges();
    auto nodes = graph.getNodes();
    graph.clear();
    for (auto e : edges) { delete e; }
    for (auto n : nodes) { delete n; }
}

TEST_F(FrameGraphTest, ReadRead) {
    struct PassData {
        FrameGraphId<Texture> input;
    };
    auto& pass = fg.addPass<PassData>("Pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.input = builder.create<Texture>("Input buffer", {.width=16, .height=32});
                data.input = builder.read(data.input, Texture::Usage::SAMPLEABLE);
                data.input = builder.read(data.input, Texture::Usage::COLOR_ATTACHMENT);
                builder.sideEffect();
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                EXPECT_EQ(resources.template getUsage(data.input), Texture::Usage::SAMPLEABLE | Texture::Usage::COLOR_ATTACHMENT);
            });

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    EXPECT_FALSE(fg.isCulled(pass));

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, WriteWrite) {
    struct PassData {
        FrameGraphId<Texture> output1;
        FrameGraphId<Texture> output2;
    };
    auto& pass = fg.addPass<PassData>("Pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.output1 = builder.create<Texture>("Input buffer", {.width=16, .height=32});
                data.output1 = builder.write(data.output1, Texture::Usage::UPLOADABLE);
                data.output2 = builder.write(data.output1, Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(data.output1, data.output2);
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                EXPECT_EQ(resources.template getUsage(data.output2), Texture::Usage::UPLOADABLE | Texture::Usage::COLOR_ATTACHMENT);
            });

    fg.present(pass->output2);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    EXPECT_FALSE(fg.isCulled(pass));

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, WriteRead) {
    struct PassData {
        FrameGraphId<Texture> inout;
    };
    auto& pass = fg.addPass<PassData>("Pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.inout = builder.create<Texture>("Inout buffer", {.width=16, .height=32});
                data.inout = builder.write(data.inout);
                EXPECT_ANY_THROW( builder.read(data.inout) );
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
            });

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    EXPECT_TRUE(fg.isCulled(pass));

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, Culling1) {
    struct PassData {
        FrameGraphId<Texture> out0;
        FrameGraphId<Texture> out1;
    };
    auto& pass = fg.addPass<PassData>("Pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.out0 = builder.create<Texture>("Out0 buffer", {.width=16, .height=32});
                data.out0 = builder.write(data.out0, Texture::Usage::COLOR_ATTACHMENT);
                data.out1 = builder.create<Texture>("Out1 buffer", {.width=16, .height=32});
                data.out1 = builder.write(data.out1, Texture::Usage::UPLOADABLE);
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                // even if out1 is not consumed, we expect it to exist, because this pass needs it
                EXPECT_TRUE(resources.get(data.out0).handle);
                EXPECT_TRUE(resources.get(data.out1).handle);
                EXPECT_EQ(resources.getUsage(data.out0), Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.out1), Texture::Usage::UPLOADABLE);
            });

    fg.present(pass->out0);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    EXPECT_FALSE(fg.isCulled(pass));

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, Basic) {
    struct DepthPassData {
        FrameGraphId<Texture> depth;
    };
    auto& depthPass = fg.addPass<DepthPassData>("Depth pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.depth = builder.create<Texture>("Depth Buffer", {.width=16, .height=32});
                auto rt = builder.declareRenderPass("Depth target", { .attachments = { .depth = data.depth }});
                data.depth = rt.attachments.depth;
                EXPECT_TRUE(fg.isValid(data.depth));
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& depth = resources.get(data.depth);
                EXPECT_TRUE((bool)depth.handle);
                auto rp = resources.getRenderPassInfo();
                EXPECT_EQ(rp.params.flags.discardStart, TargetBufferFlags::DEPTH);
                EXPECT_EQ(rp.params.flags.discardEnd, TargetBufferFlags::NONE);
                EXPECT_EQ(rp.params.viewport.width, 16);
                EXPECT_EQ(rp.params.viewport.height, 32);
                EXPECT_TRUE((bool)rp.target);
            });

    struct GBufferPassData {
        FrameGraphId<Texture> depth;
        FrameGraphId<Texture> gbuf1;
        FrameGraphId<Texture> gbuf2;
        FrameGraphId<Texture> gbuf3;
    };
    auto& gBufferPass = fg.addPass<GBufferPassData>("Gbuffer pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.depth = builder.read(depthPass->depth, Texture::Usage::DEPTH_ATTACHMENT);
                Texture::Descriptor desc = builder.getDescriptor(data.depth);
                data.gbuf1 = builder.create<Texture>("Gbuffer 1", desc);
                data.gbuf2 = builder.create<Texture>("Gbuffer 2", desc);
                data.gbuf3 = builder.create<Texture>("Gbuffer 3", desc);
                auto rt = builder.declareRenderPass("Gbuffer target", { .attachments = {
                        .color = { data.gbuf1, data.gbuf2, data.gbuf3 },
                        .depth = data.depth
                }});

                EXPECT_FALSE(fg.isValid(data.depth));

                data.depth = rt.attachments.depth;
                data.gbuf1 = rt.attachments.color[0];
                data.gbuf2 = rt.attachments.color[1];
                data.gbuf3 = rt.attachments.color[2];
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& depth = resources.get(data.depth);
                Texture const& gbuf1 = resources.get(data.gbuf1);
                Texture const& gbuf2 = resources.get(data.gbuf2);
                Texture const& gbuf3 = resources.get(data.gbuf3);
                EXPECT_TRUE((bool)depth.handle);
                EXPECT_TRUE((bool)gbuf1.handle);
                EXPECT_TRUE((bool)gbuf2.handle);
                EXPECT_TRUE((bool)gbuf3.handle);
                auto rp = resources.getRenderPassInfo();
                EXPECT_EQ(rp.params.flags.discardStart,
                        TargetBufferFlags::COLOR0
                        | TargetBufferFlags::COLOR1
                        | TargetBufferFlags::COLOR2);
                EXPECT_EQ(rp.params.flags.discardEnd, TargetBufferFlags::COLOR0);
                EXPECT_EQ(rp.params.viewport.width, 16);
                EXPECT_EQ(rp.params.viewport.height, 32);
                EXPECT_TRUE((bool)rp.target);
            });

    struct LightingPassData {
        FrameGraphId<Texture> lightingBuffer;
        FrameGraphId<Texture> depth;
        FrameGraphId<Texture> gbuf1;
        FrameGraphId<Texture> gbuf2;
        FrameGraphId<Texture> gbuf3;
    };
    auto& lightingPass = fg.addPass<LightingPassData>("Lighting pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.depth = builder.read(gBufferPass->depth, Texture::Usage::SAMPLEABLE);
                data.gbuf1 = gBufferPass->gbuf1;
                data.gbuf2 = builder.read(gBufferPass->gbuf2, Texture::Usage::SAMPLEABLE);
                data.gbuf3 = builder.read(gBufferPass->gbuf3, Texture::Usage::SAMPLEABLE);
                Texture::Descriptor desc = builder.getDescriptor(data.depth);
                data.lightingBuffer = builder.create<Texture>("Lighting buffer", desc);
                data.lightingBuffer = builder.declareRenderPass(data.lightingBuffer);
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& lightingBuffer = resources.get(data.lightingBuffer);
                Texture const& depth = resources.get(data.depth);
                Texture const& gbuf1 = resources.get(data.gbuf1);
                Texture const& gbuf2 = resources.get(data.gbuf2);
                Texture const& gbuf3 = resources.get(data.gbuf3);
                EXPECT_TRUE((bool)lightingBuffer.handle);
                EXPECT_TRUE((bool)depth.handle);
                EXPECT_FALSE((bool)gbuf1.handle);
                EXPECT_TRUE((bool)gbuf2.handle);
                EXPECT_TRUE((bool)gbuf3.handle);
                auto rp = resources.getRenderPassInfo();
                EXPECT_EQ(rp.params.flags.discardStart,TargetBufferFlags::COLOR0);
                EXPECT_EQ(rp.params.flags.discardEnd, TargetBufferFlags::NONE);
                EXPECT_EQ(rp.params.viewport.width, 16);
                EXPECT_EQ(rp.params.viewport.height, 32);
                EXPECT_TRUE((bool)rp.target);
            });

    struct DebugPass {
        FrameGraphId<Texture> debugBuffer;
        FrameGraphId<Texture> gbuf1;
        FrameGraphId<Texture> gbuf2;
        FrameGraphId<Texture> gbuf3;
    };
    auto& culledPass = fg.addPass<DebugPass>("DebugPass pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.gbuf1 = builder.read(lightingPass->gbuf1, Texture::Usage::SAMPLEABLE);
                data.gbuf2 = builder.read(lightingPass->gbuf2, Texture::Usage::SAMPLEABLE);
                data.gbuf3 = builder.read(lightingPass->gbuf3, Texture::Usage::SAMPLEABLE);
                Texture::Descriptor desc = builder.getDescriptor(data.gbuf1);
                data.debugBuffer = builder.create<Texture>("Debug buffer", desc);
                data.debugBuffer = builder.declareRenderPass(data.debugBuffer);
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& debugBuffer = resources.get(data.debugBuffer);
                Texture const& gbuf1 = resources.get(data.gbuf1);
                Texture const& gbuf2 = resources.get(data.gbuf2);
                Texture const& gbuf3 = resources.get(data.gbuf3);
                EXPECT_FALSE((bool)debugBuffer.handle);
                EXPECT_TRUE((bool)gbuf1.handle);
                EXPECT_TRUE((bool)gbuf2.handle);
                EXPECT_TRUE((bool)gbuf3.handle);
                auto rp = resources.getRenderPassInfo();
                EXPECT_FALSE((bool)rp.target);
            });

    struct PostPassData {
        FrameGraphId<Texture> lightingBuffer;
        FrameGraphId<Texture> backBuffer;
        struct {
            FrameGraphId<Texture> depth;
            FrameGraphId<Texture> gbuf1;
            FrameGraphId<Texture> gbuf2;
            FrameGraphId<Texture> gbuf3;
        } destroyed;
    };
    auto& postPass = fg.addPass<PostPassData>("Post pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.lightingBuffer = builder.read(lightingPass->lightingBuffer, Texture::Usage::SAMPLEABLE);
                Texture::Descriptor desc = builder.getDescriptor(data.lightingBuffer);
                data.backBuffer = builder.create<Texture>("Backbuffer", desc);
                data.backBuffer = builder.declareRenderPass(data.backBuffer);
                data.destroyed.depth = lightingPass->depth;
                data.destroyed.gbuf1 = lightingPass->gbuf1;
                data.destroyed.gbuf2 = lightingPass->gbuf2;
                data.destroyed.gbuf3 = lightingPass->gbuf3;
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& lightingBuffer = resources.get(data.lightingBuffer);
                Texture const& backBuffer = resources.get(data.backBuffer);
                EXPECT_TRUE((bool)lightingBuffer.handle);
                EXPECT_TRUE((bool)backBuffer.handle);
                EXPECT_FALSE((bool)resources.get(data.destroyed.depth).handle);
                EXPECT_FALSE((bool)resources.get(data.destroyed.gbuf1).handle);
                EXPECT_FALSE((bool)resources.get(data.destroyed.gbuf2).handle);
                EXPECT_FALSE((bool)resources.get(data.destroyed.gbuf3).handle);

                EXPECT_EQ(resources.getUsage(data.lightingBuffer),  Texture::Usage::SAMPLEABLE | Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.backBuffer),                                   Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.destroyed.depth), Texture::Usage::SAMPLEABLE | Texture::Usage::DEPTH_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.destroyed.gbuf1),                              Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.destroyed.gbuf2), Texture::Usage::SAMPLEABLE | Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.destroyed.gbuf3), Texture::Usage::SAMPLEABLE | Texture::Usage::COLOR_ATTACHMENT);

                auto rp = resources.getRenderPassInfo();
                EXPECT_EQ(rp.params.flags.discardStart,TargetBufferFlags::COLOR0);
                EXPECT_EQ(rp.params.flags.discardEnd, TargetBufferFlags::NONE);
                EXPECT_EQ(rp.params.viewport.width, 16);
                EXPECT_EQ(rp.params.viewport.height, 32);
                EXPECT_TRUE((bool)rp.target);
            });

    fg.present(postPass->backBuffer);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    EXPECT_TRUE(fg.isCulled(culledPass));

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, ImportResource) {
    Texture outputTexture{ .handle = Handle<HwTexture>{ 0x1234 }};
    Texture inputTexture{ .handle = Handle<HwTexture>{ 0x3141 }};

    FrameGraphId<Texture> output = fg.import("Imported output texture", Texture::Descriptor{
            .width = 320, .height = 200 }, Texture::Usage::COLOR_ATTACHMENT, outputTexture);
    FrameGraphId<Texture> input = fg.import("Imported input texture", Texture::Descriptor{
            .width = 640, .height = 400 }, Texture::Usage::SAMPLEABLE, inputTexture);

    EXPECT_TRUE(fg.isValid(output));
    EXPECT_TRUE(fg.isValid(input));

    struct PassData {
        FrameGraphId<Texture> input;
        FrameGraphId<Texture> output;
    };
    auto& pass = fg.addPass<PassData>("Pass", [&](FrameGraph::Builder& builder, auto& data) {
                auto const& descOutput = builder.getDescriptor(output);
                EXPECT_EQ(descOutput.width, 320);
                EXPECT_EQ(descOutput.height, 200);

                auto const& descInput = builder.getDescriptor(input);
                EXPECT_EQ(descInput.width, 640);
                EXPECT_EQ(descInput.height, 400);

                EXPECT_ANY_THROW( output = builder.write(output, Texture::Usage::UPLOADABLE) );

                data.output = builder.write(output, Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_TRUE(fg.isValid(output)); // output is expect valid here because we never read before
                EXPECT_TRUE(fg.isValid(data.output));

                data.input = builder.read(input, Texture::Usage::SAMPLEABLE);
                EXPECT_TRUE(fg.isValid(data.input));
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& output = resources.get(data.output);
                Texture const& input = resources.get(data.input);
                EXPECT_EQ(output.handle.getId(), 0x1234);
                EXPECT_EQ(input.handle.getId(), 0x3141);
            });

    fg.present(pass->output);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, SubResources1) {

    struct PassData {
        FrameGraphId<Texture> output;
        FrameGraphId<Texture> outputs[4];
    };
    auto& pass = fg.addPass<PassData>("Pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.output = builder.create<Texture>("Color buffer", {.width=16, .height=32, .levels=4});
                for (int i = 0; i < 4; i++) {
                    data.outputs[i] = builder.createSubresource(data.output, "Color mip", { .level=uint8_t(i) });
                }
                //EXPECT_TRUE(fg.isValid(data.output));
                EXPECT_TRUE(fg.isValid(data.outputs[0]));
                EXPECT_TRUE(fg.isValid(data.outputs[1]));
                EXPECT_TRUE(fg.isValid(data.outputs[2]));
                EXPECT_TRUE(fg.isValid(data.outputs[3]));

                for (int i = 0; i < 4; i++) {
                    data.outputs[i] = builder.declareRenderPass(data.outputs[i]);
                }

                EXPECT_TRUE(fg.isValid(data.outputs[0]));
                EXPECT_TRUE(fg.isValid(data.outputs[1]));
                EXPECT_TRUE(fg.isValid(data.outputs[2]));
                EXPECT_TRUE(fg.isValid(data.outputs[3]));
            },
            [=](FrameGraphResources const& resources, auto const& data,
                    backend::DriverApi& driver) {
                auto outputDesc = resources.getDescriptor(data.output);
                auto output = resources.get(data.output);
                EXPECT_TRUE(output.handle);
                EXPECT_TRUE(any(resources.getUsage(data.output) & Texture::Usage::COLOR_ATTACHMENT));
                EXPECT_TRUE(any(resources.getUsage(data.output) & Texture::Usage::SAMPLEABLE));

                EXPECT_TRUE(resources.get(data.outputs[0]).handle);
                EXPECT_TRUE(resources.get(data.outputs[1]).handle);
                EXPECT_TRUE(resources.get(data.outputs[2]).handle);
                EXPECT_TRUE(resources.get(data.outputs[3]).handle);

                EXPECT_TRUE(any(resources.getUsage(data.outputs[0]) & Texture::Usage::COLOR_ATTACHMENT));
                EXPECT_TRUE(any(resources.getUsage(data.outputs[0]) & Texture::Usage::SAMPLEABLE));

                EXPECT_EQ(resources.getUsage(data.outputs[1]), Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.outputs[2]), Texture::Usage::COLOR_ATTACHMENT);
                EXPECT_EQ(resources.getUsage(data.outputs[3]), Texture::Usage::COLOR_ATTACHMENT);

                auto rp0 = resources.getRenderPassInfo(0);
                auto rp1 = resources.getRenderPassInfo(1);
                auto rp2 = resources.getRenderPassInfo(2);
                auto rp3 = resources.getRenderPassInfo(3);
                EXPECT_TRUE(rp0.target);
                EXPECT_TRUE(rp1.target);
                EXPECT_TRUE(rp2.target);
                EXPECT_TRUE(rp3.target);

                EXPECT_EQ(resources.getSubResourceDescriptor(data.outputs[0]).level, 0);
                EXPECT_EQ(resources.getSubResourceDescriptor(data.outputs[1]).level, 1);
                EXPECT_EQ(resources.getSubResourceDescriptor(data.outputs[2]).level, 2);
                EXPECT_EQ(resources.getSubResourceDescriptor(data.outputs[3]).level, 3);

                EXPECT_EQ(rp0.params.flags.discardStart,TargetBufferFlags::COLOR0);
                EXPECT_EQ(rp1.params.flags.discardStart,TargetBufferFlags::COLOR0);
                EXPECT_EQ(rp2.params.flags.discardStart,TargetBufferFlags::COLOR0);
                EXPECT_EQ(rp3.params.flags.discardStart,TargetBufferFlags::COLOR0);

                EXPECT_EQ(rp0.params.flags.discardEnd, TargetBufferFlags::NONE);
                EXPECT_EQ(rp1.params.flags.discardEnd, TargetBufferFlags::NONE);
                EXPECT_EQ(rp2.params.flags.discardEnd, TargetBufferFlags::NONE);
                EXPECT_EQ(rp2.params.flags.discardEnd, TargetBufferFlags::NONE);
            });

    struct DebugPass {
        FrameGraphId<Texture> debugBuffer;
        FrameGraphId<Texture> subresource;
        FrameGraphId<Texture> out;
    };
    auto& debugPass = fg.addPass<DebugPass>("DebugPass pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.subresource = builder.read(pass->outputs[0], Texture::Usage::SAMPLEABLE);
                data.out = builder.write(data.subresource, Texture::Usage::UPLOADABLE);
                Texture::Descriptor desc = builder.getDescriptor(data.subresource);
                data.debugBuffer = builder.create<Texture>("Debug buffer", desc);
                data.debugBuffer = builder.declareRenderPass(data.debugBuffer);
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
                Texture const& debugBuffer = resources.get(data.debugBuffer);
                Texture const& subresource = resources.get(data.subresource);
                EXPECT_TRUE((bool)debugBuffer.handle);
                EXPECT_TRUE((bool)subresource.handle);
                auto rp = resources.getRenderPassInfo();
                EXPECT_TRUE((bool)rp.target);
            });
    fg.present(debugPass->debugBuffer);
    fg.present(debugPass->out);

    fg.present(pass->output);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, SubResources2) {

    struct UploadPassData {
        FrameGraphId<Texture> output;
    };
    auto& uploadPass = fg.addPass<UploadPassData>("Upload pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.output = builder.create<Texture>("Color buffer", {.width=16, .height=32, .levels=4});
                data.output = builder.write(data.output, Texture::Usage::UPLOADABLE);
                EXPECT_TRUE(fg.isValid(data.output));
            },
            [=](FrameGraphResources const& resources, auto const& data,
                    backend::DriverApi& driver) {
                auto outputDesc = resources.getDescriptor(data.output);
                auto output = resources.get(data.output);
                EXPECT_TRUE(output.handle);
                EXPECT_EQ(resources.getUsage(data.output),
                        Texture::Usage::UPLOADABLE | Texture::Usage::COLOR_ATTACHMENT);
            });

    struct BlitPassData {
        FrameGraphId<Texture> output;
        FrameGraphId<Texture> inputs[4];
    };
    auto& blitPass = fg.addPass<BlitPassData>("Blit pass",
            [&](FrameGraph::Builder& builder, auto& data) {
                data.output = builder.create<Texture>("Output buffer", {.width=16, .height=32});
                data.output = builder.declareRenderPass(data.output);
                for (int i = 0; i < 4; i++) {
                    data.inputs[i] = builder.createSubresource(uploadPass->output, "Color mip", { .level=uint8_t(i) });
                    EXPECT_TRUE(fg.isValid(data.inputs[i]));
                    data.inputs[i] = builder.read(data.inputs[i], Texture::Usage::COLOR_ATTACHMENT);
                    EXPECT_TRUE(fg.isValid(data.inputs[i]));
                }
            },
            [=](FrameGraphResources const& resources, auto const& data, backend::DriverApi& driver) {
            });

    fg.present(blitPass->output);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    fg.execute(driverApi);
}

TEST_F(FrameGraphTest, SubResources3) {

    struct UpstreamPassData {
        FrameGraphId<Texture> output;
    };
    auto& upstreamPass = fg.addPass<UpstreamPassData>("Upstream pass", [&](FrameGraph::Builder& builder, auto& data) {
                data.output = builder.create<Texture>("Color buffer", {.width=16, .height=32, .levels=4});
                data.output = builder.declareRenderPass(data.output);
                EXPECT_TRUE(fg.isValid(data.output));
            },
            [=](FrameGraphResources const& resources, auto const& data,
                    backend::DriverApi& driver) {
                EXPECT_TRUE(resources.get(data.output).handle);
                EXPECT_TRUE(any(resources.getUsage(data.output) & Texture::Usage::COLOR_ATTACHMENT));
            });

    struct MipmapPassData {
        FrameGraphId<Texture> input;
        FrameGraphId<Texture> output;
    };

    FrameGraphId<Texture> input = upstreamPass->output;
    for (int i = 1; i < 4; i++) {
        auto& mipmapPass = fg.addPass<MipmapPassData>("Mipmap pass",
                [&](FrameGraph::Builder& builder, auto& data) {
                    data.input = builder.read(input);
                    data.output = builder.createSubresource(upstreamPass->output, "Mip level buffer", { .level=uint8_t(i) });
                    data.output = builder.declareRenderPass(data.output);
                    EXPECT_TRUE(fg.isValid(data.output));
                    EXPECT_TRUE(fg.isValid(data.input));
                },
                [=](FrameGraphResources const& resources, auto const& data,
                        backend::DriverApi& driver) {
                    EXPECT_TRUE(resources.get(data.input).handle);
                    EXPECT_TRUE(any(resources.getUsage(data.input) & Texture::Usage::SAMPLEABLE));
                    EXPECT_TRUE(resources.get(data.output).handle);
                    EXPECT_TRUE(any(resources.getUsage(data.output) & Texture::Usage::COLOR_ATTACHMENT));
                });
        input = mipmapPass->output;
    }

    fg.present(upstreamPass->output);

    EXPECT_TRUE(fg.isAcyclic());

    fg.compile();

    fg.execute(driverApi);
}
