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

#pragma once

#include <functional>

#include <binder/Common.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <utils/StrongPointer.h>

namespace android {
namespace binder {
namespace internal {
class ClientCounterCallback;
}  // namespace internal

/**
 * Exits when all services registered through this object have 0 clients
 *
 * In order to use this class, it's expected that your service:
 * - registers all services in the process with this API
 * - configures services as oneshot in init .rc files
 * - configures services as disabled in init.rc files, unless a client is
 *   guaranteed early in boot, in which case, forcePersist should also be used
 *   to avoid races.
 * - uses 'interface' declarations in init .rc files
 *
 * For more information on init .rc configuration, see system/core/init/README.md
 **/
class LazyServiceRegistrar {
public:
    LIBBINDER_EXPORTED static LazyServiceRegistrar& getInstance();
    LIBBINDER_EXPORTED status_t
    registerService(const sp<IBinder>& service, const std::string& name = "default",
                    bool allowIsolated = false,
                    int dumpFlags = IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);
    /**
     * Force the service to persist, even when it has 0 clients.
     * If setting this flag from the server side, make sure to do so before calling
     * registerService, or there may be a race with the default dynamic shutdown.
     *
     * This should only be used if it is every eventually set to false. If a
     * service needs to persist but doesn't need to dynamically shut down,
     * prefer to control it with another mechanism such as ctl.start.
     */
    LIBBINDER_EXPORTED void forcePersist(bool persist);

    /**
     * Set a callback that is invoked when the active service count (i.e. services with clients)
     * registered with this process drops to zero (or becomes nonzero).
     * The callback takes a boolean argument, which is 'true' if there is
     * at least one service with clients.
     *
     * Callback return value:
     * - false: Default behavior for lazy services (shut down the process if there
     *          are no clients).
     * - true:  Don't shut down the process even if there are no clients.
     *
     * This callback gives a chance to:
     * 1 - Perform some additional operations before exiting;
     * 2 - Prevent the process from exiting by returning "true" from the
     *     callback.
     *
     * This method should be called before 'registerService' to avoid races.
     */
    LIBBINDER_EXPORTED void setActiveServicesCallback(
            const std::function<bool(bool)>& activeServicesCallback);

    /**
     * Try to unregister all services previously registered with 'registerService'.
     * Returns 'true' if successful. This should only be called within the callback registered by
     * setActiveServicesCallback.
     */
    LIBBINDER_EXPORTED bool tryUnregister();

    /**
     * Re-register services that were unregistered by 'tryUnregister'.
     * This method should be called in the case 'tryUnregister' fails
     * (and should be called on the same thread).
     */
    LIBBINDER_EXPORTED void reRegister();

    /**
     * Create a second instance of lazy service registrar.
     *
     * WARNING: dangerous! DO NOT USE THIS - LazyServiceRegistrar
     * should be single-instanced, so that the service will only
     * shut down when all services are unused. A separate instance
     * is only used to test race conditions.
     */
    LIBBINDER_EXPORTED static LazyServiceRegistrar createExtraTestInstance();

private:
    std::shared_ptr<internal::ClientCounterCallback> mClientCC;
    LazyServiceRegistrar();
};

}  // namespace binder
}  // namespace android
