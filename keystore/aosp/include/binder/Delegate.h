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

#include <binder/Common.h>
#include <binder/IBinder.h>

#if !defined(__BIONIC__) && defined(BINDER_ENABLE_LIBLOG_ASSERT)
#include <log/log.h>
#define __assert(file, line, message) LOG_ALWAYS_FATAL(file ":" #line ": " message)
#endif

#ifndef __BIONIC__
#ifndef __assert

// defined differently by liblog
#pragma push_macro("LOG_PRI")
#ifdef LOG_PRI
#undef LOG_PRI
#endif
#include <syslog.h>
#pragma pop_macro("LOG_PRI")

#define __assert(a, b, c)          \
    do {                           \
        syslog(LOG_ERR, a ": " c); \
        abort();                   \
    } while (false)
#endif // __assert
#endif // __BIONIC__

namespace android {

/*
 * Used to manage AIDL's *Delegator types.
 * This is used to:
 * - create a new *Delegator object that delegates to the binder argument.
 * - or return an existing *Delegator object that already delegates to the
 * binder argument.
 * - or return the underlying delegate binder if the binder argument is a
 * *Delegator itself.
 *
 * @param binder - the binder to delegate to or unwrap
 *
 * @return pointer to the *Delegator object or the unwrapped binder object
 */
template <typename T>
sp<T> delegate(const sp<T>& binder) {
    const void* isDelegatorId = &T::descriptor;
    const void* hasDelegatorId = &T::descriptor + 1;
    // is binder itself a delegator?
    if (T::asBinder(binder)->findObject(isDelegatorId)) {
        if (T::asBinder(binder)->findObject(hasDelegatorId)) {
            __assert(__FILE__, __LINE__,
                     "This binder has a delegator and is also delegator itself! This is "
                     "likely an unintended mixing of binders.");
            return nullptr;
        }
        // unwrap the delegator
        return static_cast<typename T::DefaultDelegator*>(binder.get())->getImpl();
    }

    struct MakeArgs {
        const sp<T>* binder;
        const void* id;
    } makeArgs;
    makeArgs.binder = &binder;
    makeArgs.id = isDelegatorId;

    // the binder is not a delegator, so construct one
    sp<IBinder> newDelegator = T::asBinder(binder)->lookupOrCreateWeak(
            hasDelegatorId,
            [](const void* args) -> sp<IBinder> {
                auto delegator = sp<typename T::DefaultDelegator>::make(
                        *static_cast<const MakeArgs*>(args)->binder);
                // make sure we know this binder is a delegator by attaching a unique ID
                (void)delegator->attachObject(static_cast<const MakeArgs*>(args)->id,
                                              reinterpret_cast<void*>(0x1), nullptr, nullptr);
                return delegator;
            },
            static_cast<const void*>(&makeArgs));
    return sp<typename T::DefaultDelegator>::cast(newDelegator);
}

} // namespace android
