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
#include <binder/IBinder.h>
#include <binder/RpcThreads.h>
#include <binder/unique_fd.h>

#include <map>
#include <optional>
#include <unordered_map>
#include <variant>

// ---------------------------------------------------------------------------
namespace android {

class IPCThreadState;
class RpcSession;
class RpcState;
namespace internal {
class Stability;
}
class ProcessState;

using binder_proxy_limit_callback = std::function<void(int)>;
using binder_proxy_warning_callback = std::function<void(int)>;

class BpBinder : public IBinder {
public:
    /**
     * Return value:
     * true - this is associated with a socket RpcSession
     * false - (usual) binder over e.g. /dev/binder
     */
    LIBBINDER_EXPORTED bool isRpcBinder() const;

    LIBBINDER_EXPORTED virtual const String16& getInterfaceDescriptor() const;
    LIBBINDER_EXPORTED virtual bool isBinderAlive() const;
    LIBBINDER_EXPORTED virtual status_t pingBinder();
    LIBBINDER_EXPORTED virtual status_t dump(int fd, const Vector<String16>& args);

    // NOLINTNEXTLINE(google-default-arguments)
    LIBBINDER_EXPORTED virtual status_t transact(uint32_t code, const Parcel& data, Parcel* reply,
                                                 uint32_t flags = 0) final;

    // NOLINTNEXTLINE(google-default-arguments)
    LIBBINDER_EXPORTED virtual status_t linkToDeath(const sp<DeathRecipient>& recipient,
                                                    void* cookie = nullptr, uint32_t flags = 0);

    // NOLINTNEXTLINE(google-default-arguments)
    LIBBINDER_EXPORTED virtual status_t unlinkToDeath(const wp<DeathRecipient>& recipient,
                                                      void* cookie = nullptr, uint32_t flags = 0,
                                                      wp<DeathRecipient>* outRecipient = nullptr);

    [[nodiscard]] status_t addFrozenStateChangeCallback(
            const wp<FrozenStateChangeCallback>& recipient);

    [[nodiscard]] status_t removeFrozenStateChangeCallback(
            const wp<FrozenStateChangeCallback>& recipient);

    LIBBINDER_EXPORTED virtual void* attachObject(const void* objectID, void* object,
                                                  void* cleanupCookie,
                                                  object_cleanup_func func) final;
    LIBBINDER_EXPORTED virtual void* findObject(const void* objectID) const final;
    LIBBINDER_EXPORTED virtual void* detachObject(const void* objectID) final;
    LIBBINDER_EXPORTED void withLock(const std::function<void()>& doWithLock);
    LIBBINDER_EXPORTED sp<IBinder> lookupOrCreateWeak(const void* objectID,
                                                      IBinder::object_make_func make,
                                                      const void* makeArgs);
    LIBBINDER_EXPORTED virtual BpBinder* remoteBinder();

    LIBBINDER_EXPORTED void sendObituary();

    LIBBINDER_EXPORTED static uint32_t getBinderProxyCount(uint32_t uid);
    LIBBINDER_EXPORTED static void getCountByUid(Vector<uint32_t>& uids, Vector<uint32_t>& counts);
    LIBBINDER_EXPORTED static void enableCountByUid();
    LIBBINDER_EXPORTED static void disableCountByUid();
    LIBBINDER_EXPORTED static void setCountByUidEnabled(bool enable);
    LIBBINDER_EXPORTED static void setBinderProxyCountEventCallback(
            binder_proxy_limit_callback cbl, binder_proxy_warning_callback cbw);
    LIBBINDER_EXPORTED static void setBinderProxyCountWatermarks(int high, int low, int warning);
    LIBBINDER_EXPORTED static uint32_t getBinderProxyCount();

    LIBBINDER_EXPORTED std::optional<int32_t> getDebugBinderHandle() const;

    // Start recording transactions to the unique_fd.
    // See RecordedTransaction.h for more details.
    LIBBINDER_EXPORTED status_t startRecordingBinder(const binder::unique_fd& fd);
    // Stop the current recording.
    LIBBINDER_EXPORTED status_t stopRecordingBinder();

    // Note: This class is not thread safe so protect uses of it when necessary
    class ObjectManager {
    public:
        ObjectManager();
        ~ObjectManager();

        void* attach(const void* objectID, void* object, void* cleanupCookie,
                     IBinder::object_cleanup_func func);
        void* find(const void* objectID) const;
        void* detach(const void* objectID);
        sp<IBinder> lookupOrCreateWeak(const void* objectID, IBinder::object_make_func make,
                                       const void* makeArgs);

    private:
        ObjectManager(const ObjectManager&);
        ObjectManager& operator=(const ObjectManager&);

        struct entry_t {
            void* object = nullptr;
            void* cleanupCookie = nullptr;
            IBinder::object_cleanup_func func = nullptr;
        };

        std::map<const void*, entry_t> mObjects;
    };

    class PrivateAccessor {
    private:
        friend class BpBinder;
        friend class ::android::Parcel;
        friend class ::android::ProcessState;
        friend class ::android::RpcSession;
        friend class ::android::RpcState;
        friend class ::android::IPCThreadState;
        explicit PrivateAccessor(const BpBinder* binder)
              : mBinder(binder), mMutableBinder(nullptr) {}
        explicit PrivateAccessor(BpBinder* binder) : mBinder(binder), mMutableBinder(binder) {}

        static sp<BpBinder> create(int32_t handle, std::function<void()>* postTask) {
            return BpBinder::create(handle, postTask);
        }
        static sp<BpBinder> create(const sp<RpcSession>& session, uint64_t address) {
            return BpBinder::create(session, address);
        }

        // valid if !isRpcBinder
        int32_t binderHandle() const { return mBinder->binderHandle(); }

        // valid if isRpcBinder
        uint64_t rpcAddress() const { return mBinder->rpcAddress(); }
        const sp<RpcSession>& rpcSession() const { return mBinder->rpcSession(); }

        void onFrozenStateChanged(bool isFrozen) { mMutableBinder->onFrozenStateChanged(isFrozen); }
        const BpBinder* mBinder;
        BpBinder* mMutableBinder;
    };

    LIBBINDER_EXPORTED const PrivateAccessor getPrivateAccessor() const {
        return PrivateAccessor(this);
    }

    PrivateAccessor getPrivateAccessor() { return PrivateAccessor(this); }

private:
    friend PrivateAccessor;
    friend class sp<BpBinder>;

    static sp<BpBinder> create(int32_t handle, std::function<void()>* postTask);
    static sp<BpBinder> create(const sp<RpcSession>& session, uint64_t address);

    struct BinderHandle {
        int32_t handle;
    };
    struct RpcHandle {
        sp<RpcSession> session;
        uint64_t address;
    };
    using Handle = std::variant<BinderHandle, RpcHandle>;

    int32_t binderHandle() const;
    uint64_t rpcAddress() const;
    const sp<RpcSession>& rpcSession() const;

    explicit BpBinder(Handle&& handle);
    BpBinder(BinderHandle&& handle, int32_t trackedUid);
    explicit BpBinder(RpcHandle&& handle);

    virtual ~BpBinder();
    virtual void onFirstRef();
    virtual void onLastStrongRef(const void* id);
    virtual bool onIncStrongAttempted(uint32_t flags, const void* id);

    friend ::android::internal::Stability;

    int32_t mStability;
    Handle mHandle;

    struct Obituary {
        wp<DeathRecipient> recipient;
        void* cookie;
        uint32_t flags;
    };

    void onFrozenStateChanged(bool isFrozen);

    struct FrozenStateChange {
        bool isFrozen = false;
        Vector<wp<FrozenStateChangeCallback>> callbacks;
        bool initialStateReceived = false;
    };

    void reportOneDeath(const Obituary& obit);
    bool isDescriptorCached() const;

    mutable RpcMutex mLock;
    volatile int32_t mAlive;
    volatile int32_t mObitsSent;
    Vector<Obituary>* mObituaries;
    std::unique_ptr<FrozenStateChange> mFrozen;
    ObjectManager mObjectMgr;
    mutable String16 mDescriptorCache;
    int32_t mTrackedUid;

    static RpcMutex sTrackingLock;
    static std::unordered_map<int32_t, uint32_t> sTrackingMap;
    static int sNumTrackedUids;
    static std::atomic_bool sCountByUidEnabled;
    static binder_proxy_limit_callback sLimitCallback;
    static uint32_t sBinderProxyCountHighWatermark;
    static uint32_t sBinderProxyCountLowWatermark;
    static bool sBinderProxyThrottleCreate;
    static std::unordered_map<int32_t, uint32_t> sLastLimitCallbackMap;
    static std::atomic<uint32_t> sBinderProxyCount;
    static std::atomic<uint32_t> sBinderProxyCountWarned;
    static binder_proxy_warning_callback sWarningCallback;
    static uint32_t sBinderProxyCountWarningWatermark;
};

} // namespace android

// ---------------------------------------------------------------------------
