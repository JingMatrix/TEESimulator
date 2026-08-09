/*
 * Copyright (C) 2007 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <binder/Common.h>
#include <binder/IMemory.h>
#include <binder/MemoryHeapBase.h>

namespace android {
// ----------------------------------------------------------------------------

class SimpleBestFitAllocator;

// ----------------------------------------------------------------------------

class MemoryDealer : public RefBase {
public:
    LIBBINDER_EXPORTED explicit MemoryDealer(
            size_t size, const char* name = nullptr,
            uint32_t flags = 0 /* or bits such as MemoryHeapBase::READ_ONLY */);

    LIBBINDER_EXPORTED virtual sp<IMemory> allocate(size_t size);
    LIBBINDER_EXPORTED virtual void dump(const char* what) const;

    // allocations are aligned to some value. return that value so clients can account for it.
    LIBBINDER_EXPORTED static size_t getAllocationAlignment();

    sp<IMemoryHeap> getMemoryHeap() const { return heap(); }

protected:
    LIBBINDER_EXPORTED virtual ~MemoryDealer();

private:
    friend class Allocation;
    virtual void                deallocate(size_t offset);
    LIBBINDER_EXPORTED const sp<IMemoryHeap>& heap() const;
    SimpleBestFitAllocator*     allocator() const;

    sp<IMemoryHeap>             mHeap;
    SimpleBestFitAllocator*     mAllocator;
};

// ----------------------------------------------------------------------------
} // namespace android
