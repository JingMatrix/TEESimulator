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
#include <utils/String16.h>
#include <utils/String8.h>

#include <pthread.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

// ---------------------------------------------------------------------------
namespace android {

class IPCThreadState;

/**
 * Kernel binder process state. All operations here refer to kernel binder. This
 * object is allocated per process.
 */
class ProcessState : public virtual RefBase {
public:
    LIBBINDER_EXPORTED static sp<ProcessState> self();
    LIBBINDER_EXPORTED static sp<ProcessState> selfOrNull();

    LIBBINDER_EXPORTED static bool isVndservicemanagerEnabled();

    /* initWithDriver() can be used to configure libbinder to use
     * a different binder driver dev node. It must be called *before*
     * any call to ProcessState::self(). The default is /dev/vndbinder
     * for processes built with the VNDK and /dev/binder for those
     * which are not.
     *
     * If this is called with nullptr, the behavior is the same as selfOrNull.
     */
    LIBBINDER_EXPORTED static sp<ProcessState> initWithDriver(const char* driver);

    LIBBINDER_EXPORTED sp<IBinder> getContextObject(const sp<IBinder>& caller);

    // This should be called before startThreadPool at the beginning
    // of a program, and libraries should never call it because programs
    // should configure their own threadpools. The threadpool size can
    // never be decreased.
    //
    // The 'maxThreads' value refers to the total number of threads
    // that will be started by the kernel. This is in addition to any
    // threads started by 'startThreadPool' or 'joinRpcThreadpool'.
    LIBBINDER_EXPORTED status_t setThreadPoolMaxThreadCount(size_t maxThreads);

    // Libraries should not call this, as processes should configure
    // threadpools themselves. Should be called in the main function
    // directly before any code executes or joins the threadpool.
    //
    // Starts one thread, PLUS those requested in setThreadPoolMaxThreadCount,
    // PLUS those manually requested in joinThreadPool.
    //
    // For instance, if setThreadPoolMaxCount(3) is called and
    // startThreadpPool (+1 thread) and joinThreadPool (+1 thread)
    // are all called, then up to 5 threads can be started.
    LIBBINDER_EXPORTED void startThreadPool();

    [[nodiscard]] LIBBINDER_EXPORTED bool becomeContextManager();

    LIBBINDER_EXPORTED sp<IBinder> getStrongProxyForHandle(int32_t handle);
    LIBBINDER_EXPORTED void expungeHandle(int32_t handle, IBinder* binder);

    // TODO: deprecate.
    LIBBINDER_EXPORTED void spawnPooledThread(bool isMain);

    LIBBINDER_EXPORTED status_t enableOnewaySpamDetection(bool enable);

    // Set the name of the current thread to look like a threadpool
    // thread. Typically this is called before joinThreadPool.
    //
    // TODO: remove this API, and automatically set it intelligently.
    LIBBINDER_EXPORTED void giveThreadPoolName();

    LIBBINDER_EXPORTED String8 getDriverName();

    LIBBINDER_EXPORTED ssize_t getKernelReferences(size_t count, uintptr_t* buf);

    // Only usable by the context manager.
    // This refcount includes:
    // 1. Strong references to the node by this and other processes
    // 2. Temporary strong references held by the kernel during a
    //    transaction on the node.
    // It does NOT include local strong references to the node
    LIBBINDER_EXPORTED ssize_t getStrongRefCountForNode(const sp<BpBinder>& binder);

    enum class CallRestriction {
        // all calls okay
        NONE,
        // log when calls are blocking
        ERROR_IF_NOT_ONEWAY,
        // abort process on blocking calls
        FATAL_IF_NOT_ONEWAY,
    };
    // Sets calling restrictions for all transactions in this process. This must be called
    // before any threads are spawned.
    LIBBINDER_EXPORTED void setCallRestriction(CallRestriction restriction);

    /**
     * Get the max number of threads that have joined the thread pool.
     * This includes kernel started threads, user joined threads and polling
     * threads if used.
     */
    LIBBINDER_EXPORTED size_t getThreadPoolMaxTotalThreadCount() const;

    /**
     * Check to see if the thread pool has started.
     */
    LIBBINDER_EXPORTED bool isThreadPoolStarted() const;

    enum class DriverFeature {
        ONEWAY_SPAM_DETECTION,
        EXTENDED_ERROR,
        FREEZE_NOTIFICATION,
    };
    // Determine whether a feature is supported by the binder driver.
    LIBBINDER_EXPORTED static bool isDriverFeatureEnabled(const DriverFeature feature);

private:
    static sp<ProcessState> init(const char* defaultDriver, bool requireDefault);

    void checkExpectingThreadPoolStart() const;

    static void onFork();
    static void parentPostFork();
    static void childPostFork();

    friend class IPCThreadState;
    friend class sp<ProcessState>;

    explicit ProcessState(const char* driver);
    ~ProcessState();

    ProcessState(const ProcessState& o);
    ProcessState& operator=(const ProcessState& o);
    String8 makeBinderThreadName();

    struct handle_entry {
        IBinder* binder;
        RefBase::weakref_type* refs;
    };

    handle_entry* lookupHandleLocked(int32_t handle);

    String8 mDriverName;
    int mDriverFD;
    void* mVMStart;

    mutable std::mutex mOnThreadAvailableLock;
    std::condition_variable mOnThreadAvailableCondVar;
    // Number of threads waiting on `mOnThreadAvailableCondVar`.
    std::atomic_int64_t mOnThreadAvailableWaiting = 0;

    // Number of binder threads current executing a command.
    std::atomic_size_t mExecutingThreadsCount;
    // Maximum number of lazy threads to be started in the threadpool by the kernel.
    std::atomic_size_t mMaxThreads;
    // Current number of threads inside the thread pool.
    std::atomic_size_t mCurrentThreads;
    // Current number of pooled threads inside the thread pool.
    std::atomic_size_t mKernelStartedThreads;
    // Time when thread pool was emptied
    std::atomic<std::chrono::steady_clock::time_point> mStarvationStartTime;

    static constexpr auto never = &std::chrono::steady_clock::time_point::min;

    mutable std::mutex mLock; // protects everything below.

    Vector<handle_entry> mHandleToObject;

    bool mForked;
    std::atomic_bool mThreadPoolStarted;
    std::atomic_int32_t mThreadPoolSeq;

    CallRestriction mCallRestriction;
};

} // namespace android

// ---------------------------------------------------------------------------
