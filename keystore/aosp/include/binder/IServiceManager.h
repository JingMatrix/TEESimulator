/*
 * Copyright (C) 2005 The Android Open Source Project
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
#include <binder/IInterface.h>
// Trusty has its own definition of socket APIs from trusty_ipc.h
#ifndef __TRUSTY__
#include <sys/socket.h>
#endif // __TRUSTY__
#include <utils/String16.h>
#include <utils/Vector.h>
#include <optional>
#include <set>

namespace android {

/**
 * Service manager for C++ services.
 *
 * IInterface is only for legacy ABI compatibility
 */
class LIBBINDER_EXPORTED IServiceManager : public IInterface {
public:
    // for ABI compatibility
    virtual const String16& getInterfaceDescriptor() const;

    IServiceManager();
    virtual ~IServiceManager();

    /**
     * Must match values in IServiceManager.aidl
     */
    /* Allows services to dump sections according to priorities. */
    static const int DUMP_FLAG_PRIORITY_CRITICAL = 1 << 0;
    static const int DUMP_FLAG_PRIORITY_HIGH = 1 << 1;
    static const int DUMP_FLAG_PRIORITY_NORMAL = 1 << 2;
    /**
     * Services are by default registered with a DEFAULT dump priority. DEFAULT priority has the
     * same priority as NORMAL priority but the services are not called with dump priority
     * arguments.
     */
    static const int DUMP_FLAG_PRIORITY_DEFAULT = 1 << 3;
    static const int DUMP_FLAG_PRIORITY_ALL = DUMP_FLAG_PRIORITY_CRITICAL |
            DUMP_FLAG_PRIORITY_HIGH | DUMP_FLAG_PRIORITY_NORMAL | DUMP_FLAG_PRIORITY_DEFAULT;
    static const int DUMP_FLAG_PROTO = 1 << 4;

    /**
     * Retrieve an existing service, blocking for a few seconds if it doesn't yet exist. This
     * does polling. A more efficient way to make sure you unblock as soon as the service is
     * available is to use waitForService or to use service notifications.
     *
     * Warning: when using this API, typically, you should call it in a loop. It's dangerous to
     * assume that nullptr could mean that the service is not available. The service could just
     * be starting. Generally, whether a service exists, this information should be declared
     * externally (for instance, an Android feature might imply the existence of a service,
     * a system property, or in the case of services in the VINTF manifest, it can be checked
     * with isDeclared).
     */
    [[deprecated("this polls for 5s, prefer waitForService or checkService")]]
    virtual sp<IBinder> getService(const String16& name) const = 0;

    /**
     * Retrieve an existing service, non-blocking.
     */
    virtual sp<IBinder>         checkService( const String16& name) const = 0;

    /**
     * Register a service.
     *
     * Note:
     * This status_t return value may be an exception code from an underlying
     * Status type that doesn't have a representive error code in
     * utils/Errors.h.
     * One example of this is a return value of -7
     * (Status::Exception::EX_UNSUPPORTED_OPERATION) when the service manager
     * process is not installed on the device when addService is called.
     */
    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t addService(const String16& name, const sp<IBinder>& service,
                                bool allowIsolated = false,
                                int dumpsysFlags = DUMP_FLAG_PRIORITY_DEFAULT) = 0;

    /**
     * Return list of all existing services.
     */
    // NOLINTNEXTLINE(google-default-arguments)
    virtual Vector<String16> listServices(int dumpsysFlags = DUMP_FLAG_PRIORITY_ALL) = 0;

    /**
     * Efficiently wait for a service.
     *
     * Returns nullptr only for permission problem or fatal error.
     */
    virtual sp<IBinder> waitForService(const String16& name) = 0;

    /**
     * Check if a service is declared (e.g. VINTF manifest).
     *
     * If this returns true, waitForService should always be able to return the
     * service.
     */
    virtual bool isDeclared(const String16& name) = 0;

    /**
     * Get all instances of a service as declared in the VINTF manifest
     */
    virtual Vector<String16> getDeclaredInstances(const String16& interface) = 0;

    /**
     * If this instance is updatable via an APEX, returns the APEX with which
     * this can be updated.
     */
    virtual std::optional<String16> updatableViaApex(const String16& name) = 0;

    /**
     * Returns all instances which are updatable via the APEX. Instance names are fully qualified
     * like `pack.age.IFoo/default`.
     */
    virtual Vector<String16> getUpdatableNames(const String16& apexName) = 0;

    /**
     * If this instance has declared remote connection information, returns
     * the ConnectionInfo.
     */
    struct ConnectionInfo {
        std::string ipAddress;
        unsigned int port;
    };
    virtual std::optional<ConnectionInfo> getConnectionInfo(const String16& name) = 0;

    struct LocalRegistrationCallback : public virtual RefBase {
        virtual void onServiceRegistration(const String16& instance, const sp<IBinder>& binder) = 0;
        virtual ~LocalRegistrationCallback() {}
    };

    virtual status_t registerForNotifications(const String16& name,
                                              const sp<LocalRegistrationCallback>& callback) = 0;

    virtual status_t unregisterForNotifications(const String16& name,
                                                const sp<LocalRegistrationCallback>& callback) = 0;

    struct ServiceDebugInfo {
        std::string name;
        int pid;
    };
    virtual std::vector<ServiceDebugInfo> getServiceDebugInfo() = 0;

    /**
     * Directly enable or disable caching binder during addService calls.
     * Only used for testing. This is enabled by default.
     */
    virtual void enableAddServiceCache(bool value) = 0;
};

LIBBINDER_EXPORTED sp<IServiceManager> defaultServiceManager();

/**
 * Directly set the default service manager. Only used for testing.
 * Note that the caller is responsible for caling this method
 * *before* any call to defaultServiceManager(); if the latter is
 * called first, setDefaultServiceManager() will abort.
 */
LIBBINDER_EXPORTED void setDefaultServiceManager(const sp<IServiceManager>& sm);

template<typename INTERFACE>
sp<INTERFACE> waitForService(const String16& name) {
    const sp<IServiceManager> sm = defaultServiceManager();
    return interface_cast<INTERFACE>(sm->waitForService(name));
}

template<typename INTERFACE>
sp<INTERFACE> waitForDeclaredService(const String16& name) {
    const sp<IServiceManager> sm = defaultServiceManager();
    if (!sm->isDeclared(name)) return nullptr;
    return interface_cast<INTERFACE>(sm->waitForService(name));
}

template <typename INTERFACE>
sp<INTERFACE> checkDeclaredService(const String16& name) {
    const sp<IServiceManager> sm = defaultServiceManager();
    if (!sm->isDeclared(name)) return nullptr;
    return interface_cast<INTERFACE>(sm->checkService(name));
}

template<typename INTERFACE>
sp<INTERFACE> waitForVintfService(
        const String16& instance = String16("default")) {
    return waitForDeclaredService<INTERFACE>(
        INTERFACE::descriptor + String16("/") + instance);
}

template<typename INTERFACE>
sp<INTERFACE> checkVintfService(
        const String16& instance = String16("default")) {
    return checkDeclaredService<INTERFACE>(
        INTERFACE::descriptor + String16("/") + instance);
}

template<typename INTERFACE>
status_t getService(const String16& name, sp<INTERFACE>* outService)
{
    const sp<IServiceManager> sm = defaultServiceManager();
    if (sm != nullptr) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        *outService = interface_cast<INTERFACE>(sm->getService(name));
#pragma clang diagnostic pop // getService deprecation
        if ((*outService) != nullptr) return NO_ERROR;
    }
    return NAME_NOT_FOUND;
}

LIBBINDER_EXPORTED void* openDeclaredPassthroughHal(const String16& interface,
                                                    const String16& instance, int flag);

LIBBINDER_EXPORTED bool checkCallingPermission(const String16& permission);
LIBBINDER_EXPORTED bool checkCallingPermission(const String16& permission, int32_t* outPid,
                                               int32_t* outUid);
LIBBINDER_EXPORTED bool checkPermission(const String16& permission, pid_t pid, uid_t uid,
                                        bool logPermissionFailure = true);

// ----------------------------------------------------------------------
// Trusty's definition of the socket APIs does not include sockaddr types
#ifndef __TRUSTY__
typedef std::function<status_t(const String16& name, sockaddr* outAddr, socklen_t addrSize)>
        RpcSocketAddressProvider;

/**
 * This callback provides a way for clients to get access to remote services by
 * providing an Accessor object from libbinder that can connect to the remote
 * service over sockets.
 *
 * \param instance name of the service that the callback will provide an
 *        Accessor for. The provided accessor will be used to set up a client
 *        RPC connection in libbinder in order to return a binder for the
 *        associated remote service.
 *
 * \return IBinder of the Accessor object that libbinder implements.
 *         nullptr if the provider callback doesn't know how to reach the
 *         service or doesn't want to provide access for any other reason.
 */
typedef std::function<sp<IBinder>(const String16& instance)> RpcAccessorProvider;

class AccessorProvider;

/**
 * Register a RpcAccessorProvider for the service manager APIs.
 *
 * \param instances that the RpcAccessorProvider knows about and can provide an
 *        Accessor for.
 * \param provider callback that generates Accessors.
 *
 * \return A pointer used as a recept for the successful addition of the
 *         AccessorProvider. This is needed to unregister it later.
 */
[[nodiscard]] LIBBINDER_EXPORTED std::weak_ptr<AccessorProvider> addAccessorProvider(
        std::set<std::string>&& instances, RpcAccessorProvider&& providerCallback);

/**
 * Remove an accessor provider using the pointer provided by addAccessorProvider
 * along with the cookie pointer that was used.
 *
 * \param provider cookie that was returned by addAccessorProvider to keep track
 *        of this instance.
 */
[[nodiscard]] LIBBINDER_EXPORTED status_t
removeAccessorProvider(std::weak_ptr<AccessorProvider> provider);

/**
 * Create an Accessor associated with a service that can create a socket connection based
 * on the connection info from the supplied RpcSocketAddressProvider.
 *
 * \param instance name of the service that this Accessor is associated with
 * \param connectionInfoProvider a callback that returns connection info for
 *        connecting to the service.
 * \return the binder of the IAccessor implementation from libbinder
 */
LIBBINDER_EXPORTED sp<IBinder> createAccessor(const String16& instance,
                                              RpcSocketAddressProvider&& connectionInfoProvider);

/**
 * Check to make sure this binder is the expected binder that is an IAccessor
 * associated with a specific instance.
 *
 * This helper function exists to avoid adding the IAccessor type to
 * libbinder_ndk.
 *
 * \param instance name of the service that this Accessor should be associated with
 * \param binder to validate
 *
 * \return OK if the binder is an IAccessor for `instance`
 */
LIBBINDER_EXPORTED status_t validateAccessor(const String16& instance, const sp<IBinder>& binder);

/**
 * Have libbinder wrap this IAccessor binder in an IAccessorDelegator and return
 * it.
 *
 * This is required only in very specific situations when the process that has
 * permissions to connect the to RPC service's socket and create the FD for it
 * is in a separate process from this process that wants to service the Accessor
 * binder and the communication between these two processes is binder RPC. This
 * is needed because the binder passed over the binder RPC connection can not be
 * used as a kernel binder, and needs to be wrapped by a kernel binder that can
 * then be registered with service manager.
 *
 * \param instance name of the Accessor.
 * \param binder to wrap in a Delegator and register with service manager.
 * \param outDelegator the wrapped kernel binder for IAccessorDelegator
 *
 * \return OK if the binder is an IAccessor for `instance` and the delegator was
 * successfully created.
 */
LIBBINDER_EXPORTED status_t delegateAccessor(const String16& name, const sp<IBinder>& accessor,
                                             sp<IBinder>* delegator);
#endif // __TRUSTY__

#ifndef __ANDROID__
// Create an IServiceManager that delegates the service manager on the device via adb.
// This is can be set as the default service manager at program start, so that
// defaultServiceManager() returns it:
//    int main() {
//        setDefaultServiceManager(createRpcDelegateServiceManager());
//        auto sm = defaultServiceManager();
//        // ...
//    }
// Resources are cleaned up when the object is destroyed.
//
// For each returned binder object, at most |maxOutgoingConnections| outgoing connections are
// instantiated, depending on how many the service on the device is configured with.
// Hence, only |maxOutgoingConnections| calls can be made simultaneously.
// See also RpcSession::setMaxOutgoingConnections.
struct RpcDelegateServiceManagerOptions {
    std::optional<size_t> maxOutgoingConnections;
};
LIBBINDER_EXPORTED sp<IServiceManager> createRpcDelegateServiceManager(
        const RpcDelegateServiceManagerOptions& options);
#endif

} // namespace android
