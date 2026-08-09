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
#include <binder/RpcThreads.h>
#include <binder/RpcTransport.h>
#include <binder/unique_fd.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <optional>
#include <type_traits>
#include <vector>

namespace android {

class Parcel;
class RpcServer;
class RpcServerTrusty;
class RpcSocketAddress;
class RpcState;
class RpcTransport;
class FdTrigger;

constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_NEXT = 2;
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL = 0xF0000000;
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION = 1;

// Starting with this version:
//
// * RpcWireReply is larger (4 bytes -> 20).
// * RpcWireTransaction and RpcWireReplyV1 include the parcel data size.
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_RPC_HEADER_FEATURE_EXPLICIT_PARCEL_SIZE = 1;

/**
 * This represents a session (group of connections) between a client
 * and a server. Multiple connections are needed for multiple parallel "binder"
 * calls which may also have nested calls.
 *
 * Once a binder exists in the session, if all references to all binders are dropped,
 * the session shuts down.
 */
class RpcSession final : public virtual RefBase {
public:
    // Create an RpcSession with default configuration (raw sockets).
    LIBBINDER_EXPORTED static sp<RpcSession> make();

    // Create an RpcSession with the given configuration. |serverRpcCertificateFormat| and
    // |serverCertificate| must have values or be nullopt simultaneously. If they have values, set
    // server certificate.
    LIBBINDER_EXPORTED static sp<RpcSession> make(
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory);

    /**
     * Set the maximum number of incoming threads allowed to be made (for things like callbacks).
     * By default, this is 0. This must be called before setting up this connection as a client.
     * Server sessions will inherits this value from RpcServer. Each thread will serve a
     * connection to the remote RpcSession.
     *
     * If this is called, 'shutdown' on this session must also be called.
     * Otherwise, a threadpool will leak.
     *
     * TODO(b/189955605): start these lazily - currently all are started
     */
    LIBBINDER_EXPORTED void setMaxIncomingThreads(size_t threads);
    LIBBINDER_EXPORTED size_t getMaxIncomingThreads();

    /**
     * Set the maximum number of outgoing connections allowed to be made.
     * By default, this is |kDefaultMaxOutgoingConnections|. This must be called before setting up
     * this connection as a client.
     *
     * For an RpcSession client, if you are connecting to a server which starts N threads,
     * then this must be set to >= N. If you set the maximum number of outgoing connections
     * to 1, but the server requests 10, then it would be considered an error. If you set a
     * maximum number of connections to 10, and the server requests 1, then only 1 will be
     * created. This API is used to limit the amount of resources a server can request you
     * create.
     */
    LIBBINDER_EXPORTED void setMaxOutgoingConnections(size_t connections);
    LIBBINDER_EXPORTED size_t getMaxOutgoingThreads();

    /**
     * By default, the minimum of the supported versions of the client and the
     * server will be used. Usually, this API should only be used for debugging.
     */
    [[nodiscard]] LIBBINDER_EXPORTED bool setProtocolVersion(uint32_t version);
    LIBBINDER_EXPORTED std::optional<uint32_t> getProtocolVersion();

    enum class FileDescriptorTransportMode : uint8_t {
        NONE = 0,
        // Send file descriptors via unix domain socket ancillary data.
        UNIX = 1,
        // Send file descriptors as Trusty IPC handles.
        TRUSTY = 2,
    };

    /**
     * Set the transport for sending and receiving file descriptors.
     */
    LIBBINDER_EXPORTED void setFileDescriptorTransportMode(FileDescriptorTransportMode mode);
    LIBBINDER_EXPORTED FileDescriptorTransportMode getFileDescriptorTransportMode();

    /**
     * This should be called once per thread, matching 'join' in the remote
     * process.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupUnixDomainClient(const char* path);

    /**
     * Connects to an RPC server over a nameless Unix domain socket pair.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t
    setupUnixDomainSocketBootstrapClient(binder::unique_fd bootstrap);

    /**
     * Connects to an RPC server at the CID & port.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupVsockClient(unsigned int cid, unsigned int port);

    /**
     * Connects to an RPC server at the given address and port.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t setupInetClient(const char* addr, unsigned int port);

    /**
     * Starts talking to an RPC server which has already been connected to. This
     * is expected to be used when another process has permission to connect to
     * a binder RPC service, but this process only has permission to talk to
     * that service.
     *
     * For convenience, if 'fd' is -1, 'request' will be called.
     *
     * For future compatibility, 'request' should not reference any stack data.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t
    setupPreconnectedClient(binder::unique_fd fd, std::function<binder::unique_fd()>&& request);

    /**
     * For debugging!
     *
     * Sets up an empty connection. All queries to this connection which require a
     * response will never be satisfied. All data sent here will be
     * unceremoniously cast down the bottomless pit, /dev/null.
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t addNullDebuggingClient();

    /**
     * Query the other side of the session for the root object hosted by that
     * process's RpcServer (if one exists)
     */
    LIBBINDER_EXPORTED sp<IBinder> getRootObject();

    /**
     * Query the other side of the session for the maximum number of threads
     * it supports (maximum number of concurrent non-nested synchronous transactions)
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t getRemoteMaxThreads(size_t* maxThreads);

    /**
     * See RpcTransportCtx::getCertificate
     */
    LIBBINDER_EXPORTED std::vector<uint8_t> getCertificate(RpcCertificateFormat);

    /**
     * Shuts down the service.
     *
     * For client sessions, wait can be true or false. For server sessions,
     * waiting is not currently supported (will abort).
     *
     * Warning: this is currently not active/nice (the server isn't told we're
     * shutting down). Being nicer to the server could potentially make it
     * reclaim resources faster.
     *
     * If this is called w/ 'wait' true, then this will wait for shutdown to
     * complete before returning. This will hang if it is called from the
     * session threadpool (when processing received calls).
     */
    [[nodiscard]] LIBBINDER_EXPORTED bool shutdownAndWait(bool wait);

    [[nodiscard]] LIBBINDER_EXPORTED status_t transact(const sp<IBinder>& binder, uint32_t code,
                                                       const Parcel& data, Parcel* reply,
                                                       uint32_t flags);

    /**
     * Generally, you should not call this, unless you are testing error
     * conditions, as this is called automatically by BpBinders when they are
     * deleted (this is also why a raw pointer is used here)
     */
    [[nodiscard]] LIBBINDER_EXPORTED status_t sendDecStrong(const BpBinder* binder);

    /**
     * Whether any requests are currently being processed.
     */
    LIBBINDER_EXPORTED bool hasActiveRequests();

    LIBBINDER_EXPORTED ~RpcSession();

    /**
     * Server if this session is created as part of a server (symmetrical to
     * client servers). Otherwise, nullptr.
     */
    LIBBINDER_EXPORTED sp<RpcServer> server();

    // internal only
    LIBBINDER_EXPORTED const std::unique_ptr<RpcState>& state() { return mRpcBinderState; }

    /**
     * Sets the session-specific root object. This is the object that will be used to attach
     * the IAccessor binder to the RpcSession when a binder is set up via accessor.
     */
    LIBBINDER_EXPORTED void setSessionSpecificRoot(const sp<IBinder>& sessionSpecificRoot);

private:
    friend sp<RpcSession>;
    friend RpcServer;
    friend RpcServerTrusty;
    friend RpcState;
    explicit RpcSession(std::unique_ptr<RpcTransportCtx> ctx);

    static constexpr size_t kDefaultMaxOutgoingConnections = 10;

    // internal version of setProtocolVersion that
    // optionally skips the mStartedSetup check
    [[nodiscard]] bool setProtocolVersionInternal(uint32_t version, bool checkStarted);

    // for 'target', see RpcState::sendDecStrongToTarget
    [[nodiscard]] status_t sendDecStrongToTarget(uint64_t address, size_t target);

    class EventListener : public virtual RefBase {
    public:
        virtual void onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) = 0;
        virtual void onSessionIncomingThreadEnded() = 0;
    };

    class WaitForShutdownListener : public EventListener {
    public:
        void onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) override;
        void onSessionIncomingThreadEnded() override;
        void waitForShutdown(RpcMutexUniqueLock& lock, const sp<RpcSession>& session);

    private:
        RpcConditionVariable mCv;
        std::atomic<size_t> mShutdownCount = 0;
    };
    friend WaitForShutdownListener;

    struct RpcConnection : public RefBase {
        std::unique_ptr<RpcTransport> rpcTransport;

        // whether this or another thread is currently using this fd to make
        // or receive transactions.
        std::optional<uint64_t> exclusiveTid;

        bool allowNested = false;
    };

    [[nodiscard]] status_t readId();

    // A thread joining a server must always call these functions in order, and
    // cleanup is only programmed once into join. These are in separate
    // functions in order to allow for different locks to be taken during
    // different parts of setup.
    //
    // transfer ownership of thread (usually done while a lock is taken on the
    // structure which originally owns the thread)
    void preJoinThreadOwnership(RpcMaybeThread thread);
    // pass FD to thread and read initial connection information
    struct PreJoinSetupResult {
        // Server connection object associated with this
        sp<RpcConnection> connection;
        // Status of setup
        status_t status;
    };
    PreJoinSetupResult preJoinSetup(std::unique_ptr<RpcTransport> rpcTransport);
    // join on thread passed to preJoinThreadOwnership
    static void join(sp<RpcSession>&& session, PreJoinSetupResult&& result);

    // This is a workaround to support move-only functors.
    // TODO: use std::move_only_function when it becomes available.
    template <typename Fn,
              // Fn must be a callable type taking (const std::vector<uint8_t>&, bool) and returning
              // status_t
              typename = std::enable_if_t<
                      std::is_invocable_r_v<status_t, Fn, const std::vector<uint8_t>&, bool>>>
    [[nodiscard]] status_t setupClient(Fn&& connectAndInit);
    [[nodiscard]] status_t setupSocketClient(const RpcSocketAddress& address);
    [[nodiscard]] status_t setupOneSocketConnection(const RpcSocketAddress& address,
                                                    const std::vector<uint8_t>& sessionId,
                                                    bool incoming);
    [[nodiscard]] status_t initAndAddConnection(RpcTransportFd fd,
                                                const std::vector<uint8_t>& sessionId,
                                                bool incoming);
    [[nodiscard]] status_t addIncomingConnection(std::unique_ptr<RpcTransport> rpcTransport);
    [[nodiscard]] status_t addOutgoingConnection(std::unique_ptr<RpcTransport> rpcTransport,
                                                 bool init);
    [[nodiscard]] bool setForServer(const wp<RpcServer>& server,
                                    const wp<RpcSession::EventListener>& eventListener,
                                    const std::vector<uint8_t>& sessionId,
                                    const sp<IBinder>& sessionSpecificRoot);
    sp<RpcConnection> assignIncomingConnectionToThisThread(
            std::unique_ptr<RpcTransport> rpcTransport);
    [[nodiscard]] bool removeIncomingConnection(const sp<RpcConnection>& connection);
    void clearConnectionTid(const sp<RpcConnection>& connection);

    [[nodiscard]] status_t initShutdownTrigger();

    /**
     * Checks whether any connection is active (Not polling on fd)
     */
    bool hasActiveConnection(const std::vector<sp<RpcConnection>>& connections);

    enum class ConnectionUse {
        CLIENT,
        CLIENT_ASYNC,
        CLIENT_REFCOUNT,
    };

    // Object representing exclusive access to a connection.
    class ExclusiveConnection {
    public:
        [[nodiscard]] static status_t find(const sp<RpcSession>& session, ConnectionUse use,
                                           ExclusiveConnection* connection);

        ~ExclusiveConnection();
        const sp<RpcConnection>& get() { return mConnection; }

    private:
        static void findConnection(uint64_t tid, sp<RpcConnection>* exclusive,
                                   sp<RpcConnection>* available,
                                   std::vector<sp<RpcConnection>>& sockets,
                                   size_t socketsIndexHint);

        sp<RpcSession> mSession; // avoid deallocation
        sp<RpcConnection> mConnection;

        // whether this is being used for a nested transaction (being on the same
        // thread guarantees we won't write in the middle of a message, the way
        // the wire protocol is constructed guarantees this is safe).
        bool mReentrant = false;
    };

    const std::unique_ptr<RpcTransportCtx> mCtx;

    // On the other side of a session, for each of mOutgoing here, there should
    // be one of mIncoming on the other side (and vice versa).
    //
    // For the simplest session, a single server with one client, you would
    // have:
    //  - the server has a single 'mIncoming' and a thread listening on this
    //  - the client has a single 'mOutgoing' and makes calls to this
    //  - here, when the client makes a call, the server can call back into it
    //    (nested calls), but outside of this, the client will only ever read
    //    calls from the server when it makes a call itself.
    //
    // For a more complicated case, the client might itself open up a thread to
    // serve calls to the server at all times (e.g. if it hosts a callback)

    wp<RpcServer> mForServer;                      // maybe null, for client sessions
    sp<WaitForShutdownListener> mShutdownListener; // used for client sessions
    wp<EventListener> mEventListener; // mForServer if server, mShutdownListener if client

    // session-specific root object (if a different root is used for each
    // session)
    sp<IBinder> mSessionSpecificRootObject;

    std::vector<uint8_t> mId;

    std::unique_ptr<FdTrigger> mShutdownTrigger;

    std::unique_ptr<RpcState> mRpcBinderState;

    RpcMutex mMutex; // for all below

    bool mStartedSetup = false;
    size_t mMaxIncomingThreads = 0;
    size_t mMaxOutgoingConnections = kDefaultMaxOutgoingConnections;
    std::optional<uint32_t> mProtocolVersion;
    FileDescriptorTransportMode mFileDescriptorTransportMode = FileDescriptorTransportMode::NONE;

    RpcConditionVariable mAvailableConnectionCv; // for mWaitingThreads

    std::unique_ptr<RpcTransport> mBootstrapTransport;

    struct ThreadState {
        size_t mWaitingThreads = 0;
        // hint index into clients, ++ when sending an async transaction
        size_t mOutgoingOffset = 0;
        std::vector<sp<RpcConnection>> mOutgoing;
        // max size of mIncoming. Once any thread starts down, no more can be started.
        size_t mMaxIncoming = 0;
        std::vector<sp<RpcConnection>> mIncoming;
        std::map<RpcMaybeThread::id, RpcMaybeThread> mThreads;
    } mConnections;
};

} // namespace android
