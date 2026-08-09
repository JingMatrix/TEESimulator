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

#include <pthread.h>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include <binder/Common.h>

namespace android {

#ifdef BINDER_RPC_SINGLE_THREADED
class LIBBINDER_EXPORTED RpcMutex {
public:
    void lock() {}
    void unlock() {}
};

class LIBBINDER_EXPORTED RpcMutexUniqueLock {
public:
    RpcMutexUniqueLock(RpcMutex&) {}
    void unlock() {}
};

class LIBBINDER_EXPORTED RpcMutexLockGuard {
public:
    RpcMutexLockGuard(RpcMutex&) {}
};

class LIBBINDER_EXPORTED RpcConditionVariable {
public:
    void notify_one() {}
    void notify_all() {}

    void wait(RpcMutexUniqueLock&) {}

    template <typename Predicate>
    void wait(RpcMutexUniqueLock&, Predicate stop_waiting) {
        LOG_ALWAYS_FATAL_IF(!stop_waiting(), "RpcConditionVariable::wait condition not met");
    }

    template <typename Duration>
    std::cv_status wait_for(RpcMutexUniqueLock&, const Duration&) {
        return std::cv_status::no_timeout;
    }

    template <typename Duration, typename Predicate>
    bool wait_for(RpcMutexUniqueLock&, const Duration&, Predicate stop_waiting) {
        return stop_waiting();
    }
};

class LIBBINDER_EXPORTED RpcMaybeThread {
public:
    RpcMaybeThread() = default;

    template <typename Function, typename... Args>
    RpcMaybeThread(Function&& f, Args&&... args) {
        // std::function requires a copy-constructible closure,
        // so we need to wrap both the function and its arguments
        // in a shared pointer that std::function can copy internally
        struct Vars {
            std::decay_t<Function> f;
            std::tuple<std::decay_t<Args>...> args;

            explicit Vars(Function&& f, Args&&... args)
                  : f(std::move(f)), args(std::move(args)...) {}
        };
        auto vars = std::make_shared<Vars>(std::forward<Function>(f), std::forward<Args>(args)...);
        mFunc = [vars]() { std::apply(std::move(vars->f), std::move(vars->args)); };
    }

    void join() {
        if (mFunc) {
            // Move mFunc into a temporary so we can clear mFunc before
            // executing the callback. This avoids infinite recursion if
            // the callee then calls join() again directly or indirectly.
            decltype(mFunc) func = nullptr;
            mFunc.swap(func);
            func();
        }
    }
    void detach() { join(); }

    class id {
    public:
        bool operator==(const id&) const { return true; }
        bool operator!=(const id&) const { return false; }
        bool operator<(const id&) const { return false; }
        bool operator<=(const id&) const { return true; }
        bool operator>(const id&) const { return false; }
        bool operator>=(const id&) const { return true; }
    };

    id get_id() const { return id(); }

private:
    std::function<void(void)> mFunc;
};

namespace rpc_this_thread {
static inline RpcMaybeThread::id get_id() {
    return RpcMaybeThread::id();
}
} // namespace rpc_this_thread

static inline void rpcJoinIfSingleThreaded(RpcMaybeThread& t) {
    t.join();
}
#else  // BINDER_RPC_SINGLE_THREADED
using RpcMutex = std::mutex;
using RpcMutexUniqueLock = std::unique_lock<std::mutex>;
using RpcMutexLockGuard = std::lock_guard<std::mutex>;
using RpcConditionVariable = std::condition_variable;
using RpcMaybeThread = std::thread;
namespace rpc_this_thread = std::this_thread;

static inline void rpcJoinIfSingleThreaded(RpcMaybeThread&) {}
#endif // BINDER_RPC_SINGLE_THREADED

} // namespace android
