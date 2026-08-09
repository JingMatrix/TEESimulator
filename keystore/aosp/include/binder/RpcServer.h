/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <binder/RpcSession.h>
#include <binder/RpcThreads.h>
#include <binder/RpcTransport.h>
#include <binder/unique_fd.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <bitset>
#include <mutex>
#include <thread>

namespace android {

class FdTrigger;
class RpcServerTrusty;
class RpcSocketAddress;

/**
 * This represents a server of an interface, which may be connected to by any
 * number of clients over sockets.
 *
 * Usage:
 *     auto server = RpcServer::make();
 *     // only supports one now
 *     if (!server->setup*Server(...)) {
 *         :(
 *     }
 *     server->join();
 */
class RpcServer final : public virtual RefBase, private RpcSession::EventListener {
public:
    LIBBINDER_EXPORTED static sp<RpcServer> make(
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory = nullptr);

    /**
     * Creates an RPC server that bootstraps sessions using an existing
     * Unix domain socket pair.
     *
     * Callers should create a pair of SOCK_STREAM Unix domain sockets, pass
     * one to RpcServer::setupUnixDomainSocketBootstrapServer and the other
     * to RpcSession::setupUnixDomainSocketBootstrapClient. Multiple client
     * session can be created from the client end of the pair.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t
    setupUnixDomainSocketBootstrapServer(binder::unique_fd serverFd);

    /**
     * This represents a session for responses, e.g.:
     *
     *     process A serves binder a
     *     process B opens a session to process A
     *     process B makes binder b and sends it to A
     *     A uses this 'back session' to send things back to B
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupUnixDomainServer(const char* path);

    /**
     * Sets up an RPC server with a raw socket file descriptor.
     * The socket should be created and bound to a socket address already, e.g.
     * the socket can be created in init.rc.
     *
     * This method is used in the libbinder_rpc_unstable API
     * RunInitUnixDomainRpcServer().
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupRawSocketServer(binder::unique_fd socket_fd);

    /**
     * Creates an RPC server binding to the given CID at the given port.
     *
     * Set |port| to VMADDR_PORT_ANY to pick an ephemeral port. In this case, |assignedPort|
     * will be set to the picked port number, if it is not null.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupVsockServer(unsigned bindCid, unsigned port,
                                                               unsigned* assignedPort = nullptr);

    /**
     * Creates an RPC server at the current port using IPv4.
     *
     * TODO(b/182914638): IPv6 support
     *
     * Set |port| to 0 to pick an ephemeral port; see discussion of
     * /proc/sys/net/ipv4/ip_local_port_range in ip(7). In this case, |assignedPort|
     * will be set to the picked port number, if it is not null.
     *
     * Set the IPv4 address for the socket to be listening on.
     * "127.0.0.1" allows for local connections from the same device.
     * "0.0.0.0" allows for connections on any IP address that the device may
     * have
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupInetServer(const char* address,
                                                              unsigned int port,
                                                              unsigned int* assignedPort = nullptr);

    /**
     * If setup*Server has been successful, return true. Otherwise return false.
     */
    [[nodiscard]] LIBBINDER_EXPORTED bool hasServer();

    /**
     * If hasServer(), return the server FD. Otherwise return invalid FD.
     */
    [[nodiscard]] LIBBINDER_EXPORTED binder::unique_fd releaseServer();

    /**
     * Set up server using an external FD previously set up by releaseServer().
     * Return false if there's already a server.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupExternalServer(binder::unique_fd serverFd);

    /**
     * This must be called before adding a client session. This corresponds
     * to the number of incoming connections to RpcSession objects in the
     * server, which will correspond to the number of outgoing connections
     * in client RpcSession objects.
     *
     * If this is not specified, this will be a single-threaded server.
     *
     * TODO(b/167966510): these are currently created per client, but these
     * should be shared.
     */
    LIBBINDER_EXPORTED void setMaxThreads(size_t threads);
    LIBBINDER_EXPORTED size_t getMaxThreads();

    /**
     * By default, the latest protocol version which is supported by a client is
     * used. However, this can be used in order to prevent newer protocol
     * versions from ever being used. This is expected to be useful for testing.
     */
    [[nodiscard]] LIBBINDER_EXPORTED bool setProtocolVersion(uint32_t version);

    /**
     * Set the supported transports for sending and receiving file descriptors.
     *
     * Clients will propose a mode when connecting. If the mode is not in the
     * provided list, the connection will be rejected.
     */
    LIBBINDER_EXPORTED void setSupportedFileDescriptorTransportModes(
            const std::vector<RpcSession::FileDescriptorTransportMode>& modes);

    /**
     * The root object can be retrieved by any client, without any
     * authentication. TODO(b/183988761)
     *
     * Holds a strong reference to the root object.
     */
    LIBBINDER_EXPORTED void setRootObject(const sp<IBinder>& binder);
    /**
     * Holds a weak reference to the root object.
     */
    LIBBINDER_EXPORTED void setRootObjectWeak(const wp<IBinder>& binder);
    /**
     * Allows a root object to be created for each session.
     *
     * Takes one argument: a callable that is invoked once per new session.
     * The callable takes three arguments:
     * - a weak pointer to the session. If you want to hold onto this in the root object, then
     *   you should keep a weak pointer, and promote it when needed. For instance, if you refer
     *   to this from the root object, then you could get ahold of transport-specific information.
     * - a type-erased pointer to an OS- and transport-specific address structure, e.g.,
     *   sockaddr_vm for vsock
     * - an integer representing the size in bytes of that structure. The callable should
     *   validate the size, then cast the type-erased pointer to a pointer to the actual type of the
     *   address, e.g., const void* to const sockaddr_vm*.
     */
    LIBBINDER_EXPORTED void setPerSessionRootObject(
            std::function<sp<IBinder>(wp<RpcSession> session, const void*, size_t)>&& object);
    LIBBINDER_EXPORTED sp<IBinder> getRootObject();

    /**
     * Set optional filter of incoming connections based on the peer's address.
     *
     * Takes one argument: a callable that is invoked on each accept()-ed
     * connection and returns false if the connection should be dropped.
     * See the description of setPerSessionRootObject() for details about
     * the callable's arguments.
     */
    LIBBINDER_EXPORTED void setConnectionFilter(std::function<bool(const void*, size_t)>&& filter);

    /**
     * Set optional modifier of each newly created server socket.
     *
     * The only argument is a successfully created file descriptor, not bound to an address yet.
     */
    LIBBINDER_EXPORTED void setServerSocketModifier(
            std::function<void(binder::borrowed_fd)>&& modifier);

    /**
     * See RpcTransportCtx::getCertificate
     */
    LIBBINDER_EXPORTED std::vector<uint8_t> getCertificate(RpcCertificateFormat);

    /**
     * Runs join() in a background thread. Immediately returns.
     */
    LIBBINDER_EXPORTED void start();

    /**
     * You must have at least one client session before calling this.
     *
     * If a client needs to actively terminate join, call shutdown() in a separate thread.
     *
     * At any given point, there can only be one thread calling join().
     *
     * Warning: if shutdown is called, this will return while the shutdown is
     * still occurring. To ensure that the service is fully shutdown, you might
     * want to call shutdown after 'join' returns.
     */
    LIBBINDER_EXPORTED void join();

    /**
     * Shut down any existing join(). Return true if successfully shut down, false otherwise
     * (e.g. no join() is running). Will wait for the server to be fully
     * shutdown.
     *
     * Warning: this will hang if it is called from its own thread.
     */
    [[nodiscard]] LIBBINDER_EXPORTED bool shutdown();

    /**
     * For debugging!
     */
    LIBBINDER_EXPORTED std::vector<sp<RpcSession>> listSessions();
    LIBBINDER_EXPORTED size_t numUninitializedSessions();

    /**
     * Whether any requests are currently being processed.
     */
    LIBBINDER_EXPORTED bool hasActiveRequests();

    LIBBINDER_EXPORTED ~RpcServer();

private:
    friend RpcServerTrusty;
    friend sp<RpcServer>;
    explicit RpcServer(std::unique_ptr<RpcTransportCtx> ctx);

    void onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) override;
    void onSessionIncomingThreadEnded() override;

    status_t setupExternalServer(
            binder::unique_fd serverFd,
            std::function<status_t(const RpcServer&, RpcTransportFd*)>&& acceptFn);

    static constexpr size_t kRpcAddressSize = 128;
    static void establishConnection(
            sp<RpcServer>&& server, RpcTransportFd clientFd,
            std::array<uint8_t, kRpcAddressSize> addr, size_t addrLen,
            std::function<void(sp<RpcSession>&&, RpcSession::PreJoinSetupResult&&)>&& joinFn);
    static status_t acceptSocketConnection(const RpcServer& server, RpcTransportFd* out);
    static status_t recvmsgSocketConnection(const RpcServer& server, RpcTransportFd* out);

    [[nodiscard]] status_t setupSocketServer(const RpcSocketAddress& address);

    const std::unique_ptr<RpcTransportCtx> mCtx;
    size_t mMaxThreads = 1;
    std::optional<uint32_t> mProtocolVersion;
    // A mode is supported if the N'th bit is on, where N is the mode enum's value.
    std::bitset<8> mSupportedFileDescriptorTransportModes = std::bitset<8>().set(
            static_cast<size_t>(RpcSession::FileDescriptorTransportMode::NONE));
    RpcTransportFd mServer; // socket we are accepting sessions on

    RpcMutex mLock; // for below
    std::unique_ptr<RpcMaybeThread> mJoinThread;
    bool mJoinThreadRunning = false;
    std::map<RpcMaybeThread::id, RpcMaybeThread> mConnectingThreads;

    sp<IBinder> mRootObject;
    wp<IBinder> mRootObjectWeak;
    std::function<sp<IBinder>(wp<RpcSession>, const void*, size_t)> mRootObjectFactory;
    std::function<bool(const void*, size_t)> mConnectionFilter;
    std::function<void(binder::borrowed_fd)> mServerSocketModifier;
    std::map<std::vector<uint8_t>, sp<RpcSession>> mSessions;
    std::unique_ptr<FdTrigger> mShutdownTrigger;
    RpcConditionVariable mShutdownCv;
    std::function<status_t(const RpcServer& server, RpcTransportFd* out)> mAcceptFn;
};

} // namespace android
