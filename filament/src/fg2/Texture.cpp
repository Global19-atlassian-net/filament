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

#include "fg2/Texture.h"

#include "ResourceAllocator.h"

namespace filament::fg2 {

void Texture::create(ResourceAllocatorInterface& resourceAllocator, const char* name,
        Texture::Descriptor const& descriptor, Texture::Usage usage) noexcept {
    handle = resourceAllocator.createTexture(name,
            descriptor.type, descriptor.levels, descriptor.format, descriptor.samples,
            descriptor.width, descriptor.height, descriptor.depth,
            usage);
}

void Texture::destroy(ResourceAllocatorInterface& resourceAllocator) noexcept {
    resourceAllocator.destroyTexture(handle);
    handle.clear();
}

} // namespace filament::fg2
