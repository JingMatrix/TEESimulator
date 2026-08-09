/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <utils/Errors.h>
#include <utils/String16.h>

#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>

// WARNING: deprecated - DO NOT USE - prefer to setup service directly.
//
// This class embellishes a class with a few static methods which can be used in
// limited circumstances (when one service needs to be registered and
// published). However, this is an anti-pattern:
// - these methods are aliases of existing methods, and as such, represent an
//   incremental amount of information required to understand the system but
//   which does not actually save in terms of lines of code. For instance, users
//   of this class should be surprised to know that this will start up to 16
//   threads in the binder threadpool.
// - the template instantiation costs need to be paid, even though everything
//   done here is generic.
// - the getServiceName API here is undocumented and non-local (for instance,
//   this unnecessarily assumes a single service type will only be instantiated
//   once with no arguments).
//
// So, DO NOT USE.

// ---------------------------------------------------------------------------
namespace android {

template<typename SERVICE>
class BinderService
{
public:
    static status_t publish(bool allowIsolated = false,
                            int dumpFlags = IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT) {
        sp<IServiceManager> sm(defaultServiceManager());
        return sm->addService(String16(SERVICE::getServiceName()), new SERVICE(), allowIsolated,
                              dumpFlags);
    }

    static void publishAndJoinThreadPool(
            bool allowIsolated = false,
            int dumpFlags = IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT) {
        publish(allowIsolated, dumpFlags);
        joinThreadPool();
    }

    static void instantiate() { publish(); }

    static status_t shutdown() { return NO_ERROR; }

private:
    static void joinThreadPool() {
        sp<ProcessState> ps(ProcessState::self());
        ps->startThreadPool();
        ps->giveThreadPoolName();
        IPCThreadState::self()->joinThreadPool();
    }
};


} // namespace android
// ---------------------------------------------------------------------------
