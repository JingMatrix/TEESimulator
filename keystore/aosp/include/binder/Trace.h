/*
 * Copyright (C) 2022 The Android Open Source Project
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

#if __has_include(<cutils/trace.h>)
#include <cutils/trace.h>
#endif

#include <binder/Common.h>

#ifdef ATRACE_TAG_AIDL
#if ATRACE_TAG_AIDL != (1 << 24)
#error "Mismatched ATRACE_TAG_AIDL definitions"
#endif
#else
#define ATRACE_TAG_AIDL (1 << 24)
#endif

namespace android {
namespace binder {

// Forward declarations from internal OS.h
namespace os {
// Trampoline functions allowing generated aidls to trace binder transactions without depending on
// libcutils/libutils
void trace_begin(uint64_t tag, const char* name);
void trace_end(uint64_t tag);
void trace_int(uint64_t tag, const char* name, int32_t value);
uint64_t get_trace_enabled_tags();
} // namespace os

class LIBBINDER_EXPORTED ScopedTrace {
public:
    inline ScopedTrace(uint64_t tag, const char* name) : mTag(tag) { os::trace_begin(mTag, name); }

    inline ~ScopedTrace() { os::trace_end(mTag); }

private:
    uint64_t mTag;
};

} // namespace binder
} // namespace android
