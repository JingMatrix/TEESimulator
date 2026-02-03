#include <android/binder.h>
#include <binder/Binder.h>
#include <binder/Common.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <sys/ioctl.h>
#include <utils/StrongPointer.h>

#include <atomic>
#include <cinttypes>
#include <map>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <utility>

#include "logging.hpp"
#include "lsplt.hpp"

/**
 * =========================================================================================
 *                                BINDER INTERCEPTION LOGIC
 * =========================================================================================
 *
 * [ Application / libbinder.so ]                            [ Android System / Service ]
 *           |                                                                 ^
 *           | (1. Calls ioctl(BINDER_WRITE_READ) to wait for work)            |
 *           v                                                                 |
 *    [ Kernel Driver ] <------------------------------------------------------+
 *           |
 *           | (2. Kernel has an incoming transaction for this process,
 *           |     prepares a BR_TRANSACTION command in the read_buffer)
 *           |
 *           v
 * [ return from ioctl() is HOOKED ]
 *           |
 *           +---(3. Hook inspects the read_buffer from the Kernel)
 *           |
 *           +--- If a BR_TRANSACTION targets a monitored Binder:
 *           |    (4) Rewrites the transaction's target to our BinderStub
 *           |
 *           v
 *    [ libbinder.so ]
 *           |
 *           | (5. libbinder processes the (modified) buffer and
 *           |     dispatches the command to the BinderStub)
 *           |
 *           v
 *    [ BinderStub::onTransact ]
 *           |
 *           v
 *    [ BinderInterceptor ]
 *           |
 *           +---(6. Pre-Process / Modify / Log)
 *           |
 *           +---(7. Forward to Real Target) ----> [ Real Target BBinder ]
 *           |
 *           +---(8. Post-Process Reply)
 *           |
 *           v
 *    [ (9) Return Result to libbinder ]
 *

 * --- Explanation of the Flow ---
 *
 * This diagram illustrates a "man-in-the-middle" attack on the Binder framework, achieved
 * by hooking the ioctl system call within the application's process.
 *
 *  1.  Waiting for Work:
 *      An application's binder thread calls `ioctl()` with the `BINDER_WRITE_READ` command.
 *      This call typically blocks in the kernel, waiting for incoming transactions or other commands.
 *
 *  2.  Kernel Prepares Command:
 *      When an external process sends a transaction to a service hosted in this application,
 *      the kernel driver prepares a `BR_TRANSACTION` command and places it in the `read_buffer`
 *      associated with the waiting `ioctl` call.
 *
 *  3.  Interception on Return:
 *      The `ioctl()` call returns to userspace.
 *      Our hook intercepts this return. It now has access to the `read_buffer`
 *      populated by the kernel *before* `libbinder` gets to see it.
 *
 *  4.  Hijacking:
 *      The hook parses the `read_buffer`. If it finds a `BR_TRANSACTION` command destined
 *      for a service that is registered with our `BinderInterceptor`, it rewrites the transaction data in-place.
 *      Specifically, it changes the target binder handle to that of our `BinderStub`
 *      and saves the original transaction details in a thread-local map.
 *
 *  5.  Dispatch to Stub:
 *      The hook then returns control to the original caller, `libbinder`.
 *      `libbinder` proceeds to parse the now-modified buffer.
 *      Seeing a transaction for `BinderStub`, it invokes its `onTransact` method.
 *
 *  6.  Pre-Processing:
 *      The `BinderStub` retrieves the original, unmodified transaction details from the thread-local map.
 *      It then passes control to the `BinderInterceptor`, which can log, modify,
 *      or block the transaction before it reaches its real destination.
 *
 *  7.  Forwarding:
 *      The `BinderInterceptor` forwards the (potentially modified) transaction to the original,
 *      intended `BBinder` service.
 *
 *  8.  Post-Processing:
 *      After the real service processes the transaction and generates a reply,
 *      the reply is returned to the `BinderInterceptor`,
 *      which gets a final chance to inspect or modify the result.
 *
 *  9.  Return Result:
 *      The final result is returned up the call stack to `libbinder`,
 *      which sends the reply back to the kernel driver to be delivered to the original caller.
 *
 *
 * =========================================================================================
**/

using namespace android;

// =============================================================================================
// Constants and Protocols
// =============================================================================================

namespace {
namespace intercept {

// Interceptor protocol codes (User space agreement between App and Interceptor Service)
constexpr uint32_t kRegisterInterceptor = 1;
constexpr uint32_t kUnregisterInterceptor = 2;

constexpr uint32_t kPreTransact = 1;
constexpr uint32_t kPostTransact = 2;

constexpr uint32_t kActionSkipTransaction = 1;
constexpr uint32_t kActionContinue = 2;
constexpr uint32_t kActionOverrideReply = 3;
constexpr uint32_t kActionOverrideData = 4;
constexpr uint32_t kActionContinueAndSkipPost = 5;

constexpr uint32_t kBackdoorCode = 0xdeadbeef;

// Strings for LibBinder hooks
constexpr std::string_view kBinderLibName = "/libbinder.so";
constexpr std::string_view kIoctlSymbol = "ioctl";

} // namespace intercept

// =============================================================================================
// Binder Driver Protocol Definitions (Ref: Android Kernel Header)
// =============================================================================================

// Use an X-Macro to define a list of all binder return protocols. This allows us
// to generate a string conversion function without a massive, hard-to-maintain switch statement.
#define BINDER_RETURN_COMMAND_LIST(X)   \
    X(BR_ERROR)                         \
    X(BR_OK)                            \
    X(BR_TRANSACTION_SEC_CTX)           \
    X(BR_TRANSACTION)                   \
    X(BR_REPLY)                         \
    X(BR_ACQUIRE_RESULT)                \
    X(BR_DEAD_REPLY)                    \
    X(BR_TRANSACTION_COMPLETE)          \
    X(BR_INCREFS)                       \
    X(BR_ACQUIRE)                       \
    X(BR_RELEASE)                       \
    X(BR_DECREFS)                       \
    X(BR_ATTEMPT_ACQUIRE)               \
    X(BR_NOOP)                          \
    X(BR_SPAWN_LOOPER)                  \
    X(BR_FINISHED)                      \
    X(BR_DEAD_BINDER)                   \
    X(BR_CLEAR_DEATH_NOTIFICATION_DONE) \
    X(BR_FAILED_REPLY)                  \
    X(BR_FROZEN_REPLY)                  \
    X(BR_ONEWAY_SPAM_SUSPECT)           \
    X(BR_TRANSACTION_PENDING_FROZEN)    \
    X(BR_FROZEN_BINDER)                 \
    X(BR_CLEAR_FREEZE_NOTIFICATION_DONE)

// Helper macro to generate a 'case CMD: return "CMD";' line.
#define GENERATE_CASE_STRING(CMD) \
    case CMD:                     \
        return #CMD;

/**
 * @brief Converts a binder driver return command code into its string representation.
 * @param cmd The command code (e.g., BR_TRANSACTION).
 * @return A string literal of the command name or "UNKNOWN_BR_COMMAND".
 */
const char *getBinderReturnCommandName(uint32_t cmd) {
    switch (cmd) {
        BINDER_RETURN_COMMAND_LIST(GENERATE_CASE_STRING)
    default:
        return "UNKNOWN_BR_COMMAND";
    }
}

} // namespace

// =============================================================================================
// Global State & Forward Declarations
// =============================================================================================

// Original ioctl function pointer
int (*g_original_ioctl)(int fd, int request, ...) = nullptr;

// Unique ID generator for transactions
static std::atomic<uint64_t> g_transaction_id_counter = 0;

// Context info to pass from the ioctl hook (processBinderWriteRead) to the BinderStub.
struct ThreadTransactionInfo {
    uint64_t transaction_id;
    uint32_t transaction_code;
    wp<BBinder> target_binder;

    // Default constructor
    ThreadTransactionInfo() : transaction_id(0), transaction_code(0) {}

    ThreadTransactionInfo(uint64_t id, uint32_t code, wp<BBinder> target)
        : transaction_id(id), transaction_code(code), target_binder(std::move(target)) {}
};

// A map keyed by thread ID. When ioctl intercepts a transaction intended for us,
// it pushes the info here. When the runtime calls our Stub, it pops the info.
static std::mutex g_thread_context_mutex;
static std::map<std::thread::id, std::queue<ThreadTransactionInfo>> g_thread_context_map;

// =============================================================================================
// Class: BinderInterceptor
// Logic: Manages the registry of intercepted Binders and handles the protocol (Pre/Post calls).
// =============================================================================================

class BinderInterceptor : public BBinder {
    struct RegistrationEntry {
        wp<IBinder> target;
        sp<IBinder> callback_interface;
    };

    // Reader-Writer lock for the registry to allow concurrent reads (lookups)
    mutable std::shared_mutex registry_mutex_;
    std::map<wp<IBinder>, RegistrationEntry> registry_;

public:
    BinderInterceptor() = default;

    // Checks if a specific Binder instance is currently registered for interception
    bool isBinderIntercepted(const wp<BBinder> &target) const {
        std::shared_lock lock(registry_mutex_);
        return registry_.find(target) != registry_.end();
    }

    // Main entry point for processing the "Man-in-the-Middle" logic
    bool processInterceptedTransaction(uint64_t tx_id, sp<BBinder> target, uint32_t code, const Parcel &data,
                                       Parcel *reply, uint32_t flags, status_t &result);

protected:
    // Handle configuration commands sent to the Interceptor itself
    status_t onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) override;

private:
    status_t handleRegister(const Parcel &data);
    status_t handleUnregister(const Parcel &data);

    // Helpers to serialize data for the remote callback interface
    status_t writeTransactionData(Parcel &out, uint64_t tx_id, sp<BBinder> target, uint32_t code, uint32_t flags,
                                  const Parcel &in_data) const;
};

static sp<BinderInterceptor> g_interceptor_instance = nullptr;

// =============================================================================================
// Class: BinderStub
// Logic: The "Dummy" binder that acts as the destination for intercepted calls.
//        It retrieves context from the global map and delegates to BinderInterceptor.
// =============================================================================================

class BinderStub : public BBinder {
public:
    const String16& getInterfaceDescriptor() const override {
        static const String16 kDescriptor("org.matrix.TEESimulator.BinderStub");
        return kDescriptor;
    }

protected:
    status_t onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) override {
        if (code != intercept::kBackdoorCode) {
            LOGE("BinderStub received an unexpected direct call with code %u! This is a bug or misuse.", code);
            return UNKNOWN_TRANSACTION;
        }

        ThreadTransactionInfo info;
        bool found_context = false;

        // 1. Retrieve the context for this thread (set previously by inspectAndRewriteTransaction)
        {
            std::lock_guard<std::mutex> lock(g_thread_context_mutex);
            auto it = g_thread_context_map.find(std::this_thread::get_id());
            if (it != g_thread_context_map.end() && !it->second.empty()) {
                info = std::move(it->second.front());
                it->second.pop();
                if (it->second.empty()) {
                    g_thread_context_map.erase(it); // Cleanup to prevent memory leak
                }
                found_context = true;
            }
        }

        if (!found_context) {
            LOGW("BinderStub received transaction but no context found for thread");
            return UNKNOWN_TRANSACTION;
        }

        // 2. Handle special "Backdoor" to get the Interceptor reference
        if (info.transaction_code == intercept::kBackdoorCode && info.target_binder == nullptr && reply) {
            LOGD("Backdoor handshake received.");
            reply->writeStrongBinder(g_interceptor_instance);
            return OK;
        }

        // 3. Promote the weak reference to the real target
        sp<BBinder> real_target = info.target_binder.promote();
        if (!real_target) {
            LOGE("[TX_ID: %" PRIu64 "] Target binder is dead.", info.transaction_id);
            return DEAD_OBJECT;
        }

        // 4. Delegate to the Interceptor logic
        status_t status = OK;
        bool interceptorManagedFlow = g_interceptor_instance->processInterceptedTransaction(
            info.transaction_id, real_target, info.transaction_code, data, reply, flags, status);

        // 5. If Interceptor logic says "Forward it", we call the original binder
        if (!interceptorManagedFlow) {
            LOGV("[TX_ID: %" PRIu64 "] Forwarding to original implementation.", info.transaction_id);
            status = real_target->transact(info.transaction_code, data, reply, flags);
        }

        return status;
    }
};

static sp<BinderStub> g_stub_instance = nullptr;

// =============================================================================================
// Hook Logic: IOCTL & Buffer Parsing
// =============================================================================================

namespace {

/**
 * @brief Analyses a binder transaction. If the target is monitored,
 *        hijacks the transaction by rewriting its destination to our BinderStub.
 * @param txn_data Pointer to the transaction data within the ioctl buffer.
 */
void inspectAndRewriteTransaction(binder_transaction_data *txn_data) {
    if (!txn_data || txn_data->target.ptr == 0)
        return;

    bool hijack = false;
    ThreadTransactionInfo info;

    // Check 1: Root user backdoor for retrieving the interceptor service binder
    if (txn_data->code == intercept::kBackdoorCode && txn_data->sender_euid == 0) {
        info.transaction_code = intercept::kBackdoorCode;
        info.target_binder = nullptr;
        hijack = true;
    // Check 2: Spoof uid of KeyStore requests from the daemon to bypass permission check
    } else if (txn_data->sender_euid == 0) {
        // The kernel driver fills sender_euid.
        // libbinder.so trusts this value to populate IPCThreadState.
        txn_data->sender_euid = 1000;
        LOGV("[Hook] Spoofing UID for transaction: 0 -> %d", txn_data->sender_euid);
        hijack = false; // Never hijack to avoid recursion
    // Check 3: Normal interception based on registry of monitored binders
    } else {
        // Safe casting based on Binder driver ABI
        RefBase::weakref_type *weak_ref = reinterpret_cast<RefBase::weakref_type *>(txn_data->target.ptr);

        // Try to acquire a temporary strong reference to check the object safely
        if (weak_ref && weak_ref->attemptIncStrong(nullptr)) {
            // The raw pointer to the binder object itself is stored in the cookie
            BBinder *target_binder_ptr = reinterpret_cast<BBinder *>(txn_data->cookie);

            // Create a weak pointer for the lookup and to store in our context map.
            // This is safe because we are holding a strong reference.
            wp<BBinder> wp_target = target_binder_ptr;

            if (g_interceptor_instance->isBinderIntercepted(wp_target)) {
                info.transaction_code = txn_data->code;
                info.target_binder = wp_target; // Assign the valid weak pointer
                hijack = true;
            }
            // Manually release the temporary strong reference we acquired at the start.
            target_binder_ptr->decStrong(nullptr);
        }
    }

    if (hijack) {
        uint64_t tx_id = ++g_transaction_id_counter;
        info.transaction_id = tx_id;

        LOGV("[Hook] Hijacking Transaction %" PRIu64 " (Code: %u)", tx_id, txn_data->code);

        // Rewrite the destination to our Stub
        txn_data->target.ptr = reinterpret_cast<uintptr_t>(g_stub_instance->getWeakRefs());
        txn_data->cookie = reinterpret_cast<uintptr_t>(g_stub_instance.get());
        txn_data->code = intercept::kBackdoorCode;

        // Store context for the stub to retrieve later in its onTransact
        std::lock_guard<std::mutex> lock(g_thread_context_mutex);
        g_thread_context_map[std::this_thread::get_id()].push(std::move(info));
    }
}

/**
 * @brief Parses the read buffer from a BINDER_WRITE_READ ioctl call, which contains
 *        commands sent from the kernel driver to userspace.
 * @param bwr The binder_write_read struct containing buffer pointers and sizes.
 */
void processBinderReadBuffer(const binder_write_read &bwr) {
    if (bwr.read_size == 0 || bwr.read_consumed == 0 || bwr.read_buffer == 0)
        return;

    uintptr_t ptr = bwr.read_buffer;
    uintptr_t end = ptr + bwr.read_consumed;

    LOGV("[Hook] Processing Read Buffer: Size=%llu, Consumed=%llu", bwr.read_size, bwr.read_consumed);

    while (ptr < end) {
        // Ensure we can read at least the command header
        if (end - ptr < sizeof(uint32_t))
            break;

        uint32_t cmd = *reinterpret_cast<const uint32_t *>(ptr);
        ptr += sizeof(uint32_t);

        // Calculate payload size from the ioctl command code
        size_t cmd_size = _IOC_SIZE(cmd);

        // Log the command using our generated to-string function
        LOGV("[Driver -> User] Command: %s (0x%x), DataSize: %zu", getBinderReturnCommandName(cmd), cmd, cmd_size);

        // Safety check: ensure the command's data does not exceed the buffer
        if (ptr + cmd_size > end) {
            LOGE("[Hook] Buffer overflow detected while parsing command %s", getBinderReturnCommandName(cmd));
            break;
        }

        // We are primarily interested in BR_TRANSACTION commands to intercept
        if (cmd == BR_TRANSACTION || cmd == BR_TRANSACTION_SEC_CTX) {
            binder_transaction_data *txn = nullptr;

            if (cmd == BR_TRANSACTION_SEC_CTX) {
                // The data is wrapped in a secctx struct
                auto *wrapper = reinterpret_cast<binder_transaction_data_secctx *>(ptr);
                txn = &wrapper->transaction_data;
            } else {
                txn = reinterpret_cast<binder_transaction_data *>(ptr);
            }

            inspectAndRewriteTransaction(txn);
        }

        // Advance pointer to the next command
        ptr += cmd_size;
    }
}

} // namespace

// =============================================================================================
// The Actual Hook Function
// =============================================================================================

int intercepted_ioctl(int fd, int request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    // 1. Call original kernel ioctl to let the driver do its work
    int result = g_original_ioctl(fd, request, arg);

    // 2. After the call returns, check if it was a BINDER_WRITE_READ and if it succeeded
    if (result >= 0 && request == BINDER_WRITE_READ && arg != nullptr) {
        const auto *bwr = static_cast<const binder_write_read *>(arg);

        // We only care about data read FROM the driver (i.e., incoming commands)
        if (bwr->read_consumed > 0) {
            processBinderReadBuffer(*bwr);
        }
    }

    return result;
}

// =============================================================================================
// BinderInterceptor Implementation
// =============================================================================================

// Placed at the top of the .cpp file, inside the BinderInterceptor implementation section.

#define VALIDATE_STATUS(tx_id, expr)                                                                               \
    do {                                                                                                           \
        status_t __result = (expr);                                                                                \
        if (__result != OK) {                                                                                      \
            LOGE("[TX_ID: %" PRIu64 "] Parcel operation failed in %s: '%s' returned %d", (tx_id), __func__, #expr, \
                 __result);                                                                                        \
            return __result;                                                                                       \
        }                                                                                                          \
    } while (0)

status_t BinderInterceptor::onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
    switch (code) {
    case intercept::kRegisterInterceptor:
        return handleRegister(data);
    case intercept::kUnregisterInterceptor:
        return handleUnregister(data);
    default:
        return BBinder::onTransact(code, data, reply, flags);
    }
}

status_t BinderInterceptor::handleRegister(const Parcel &data) {
    sp<IBinder> target;
    sp<IBinder> callback;

    if (data.readStrongBinder(&target) != OK || !target)
        return BAD_VALUE;
    if (data.readStrongBinder(&callback) != OK || !callback)
        return BAD_VALUE;

    // We can only intercept local Binders (BBinder), not remote proxies (BpBinder)
    if (target->localBinder() == nullptr) {
        LOGE("Cannot intercept remote binder proxies.");
        return BAD_TYPE;
    }

    wp<IBinder> weak_target = target;

    std::unique_lock lock(registry_mutex_);
    registry_[weak_target] = {weak_target, callback};

    LOGI("Interceptor registered for binder %p", target.get());
    return OK;
}

status_t BinderInterceptor::handleUnregister(const Parcel &data) {
    sp<IBinder> target;
    if (data.readStrongBinder(&target) != OK || !target)
        return BAD_VALUE;

    wp<IBinder> weak_target = target;

    std::unique_lock lock(registry_mutex_);
    if (registry_.erase(weak_target) > 0) {
        LOGI("Interceptor unregistered for binder %p", target.get());
        return OK;
    }
    LOGW("Attempted to unregister a non-existent interceptor for binder %p", target.get());
    return NAME_NOT_FOUND;
}

status_t BinderInterceptor::writeTransactionData(Parcel &out, uint64_t tx_id, sp<BBinder> target, uint32_t code,
                                                 uint32_t flags, const Parcel &in_data) const {
    // This is the data contract for communicating with the remote analysis/control tool
    VALIDATE_STATUS(tx_id, out.writeInt64(tx_id));
    VALIDATE_STATUS(tx_id, out.writeStrongBinder(target));
    VALIDATE_STATUS(tx_id, out.writeUint32(code));
    VALIDATE_STATUS(tx_id, out.writeUint32(flags));
    VALIDATE_STATUS(tx_id, out.writeInt32(IPCThreadState::self()->getCallingUid()));
    VALIDATE_STATUS(tx_id, out.writeInt32(IPCThreadState::self()->getCallingPid()));
    VALIDATE_STATUS(tx_id, out.writeUint64(in_data.dataSize()));
    VALIDATE_STATUS(tx_id, out.appendFrom(&in_data, 0, in_data.dataSize()));
    return OK;
}

bool BinderInterceptor::processInterceptedTransaction(uint64_t tx_id, sp<BBinder> target, uint32_t code,
                                                      const Parcel &request, Parcel *reply, uint32_t flags,
                                                      status_t &result) {
    sp<IBinder> callback;
    {
        std::shared_lock lock(registry_mutex_);
        auto it = registry_.find(target);
        if (it == registry_.end())
            return false; // Should not happen given logic in hook, but safe
        callback = it->second.callback_interface;
    }

    // --- Phase 1: Pre-Transaction Callback ---
    Parcel pre_req, pre_resp;
    writeTransactionData(pre_req, tx_id, target, code, flags, request);

    if (callback->transact(intercept::kPreTransact, pre_req, &pre_resp) != OK) {
        LOGW("[TX_ID: %" PRIu64 "] Pre-transaction callback failed. Forwarding original call.", tx_id);
        return false; // Callback failed, proceed as if not intercepted
    }

    int32_t action = pre_resp.readInt32();

    // ACTION: Override Reply immediately and skip the real transaction
    if (action == intercept::kActionOverrideReply) {
        if (reply) {
            result = pre_resp.readInt32(); // Read status code from response
            size_t size = pre_resp.readUint64();
            reply->setDataSize(0);
            reply->appendFrom(&pre_resp, pre_resp.dataPosition(), size);
        }
        return true; // Handled
    }

    // ACTION: Silently skip/drop the transaction
    if (action == intercept::kActionSkipTransaction) {
        result = OK; // Return OK to caller, but do nothing
        return true; // Handled
    }

    // ACTION: Skip the post-transaction hook
    if (action == intercept::kActionContinueAndSkipPost) {
        result = OK;  // Return OK to caller, but do nothing
        return false; // Forward it
    }

    // ACTION: Modify the transaction's request data before forwarding
    Parcel final_request;
    if (action == intercept::kActionOverrideData) {
        size_t size = pre_resp.readUint64();
        final_request.appendFrom(&pre_resp, pre_resp.dataPosition(), size);
    } else {
        // Default (kActionContinue): Use original data
        final_request.appendFrom(&request, 0, request.dataSize());
    }

    // --- Phase 2: Execute Original Transaction ---
    result = target->transact(code, final_request, reply, flags);

    // --- Phase 3: Post-Transaction Callback ---
    Parcel post_req, post_resp;
    writeTransactionData(post_req, tx_id, target, code, flags, final_request);

    // Append the result of the execution for the callback to see
    VALIDATE_STATUS(tx_id, post_req.writeInt32(result));
    size_t reply_size = (reply) ? reply->dataSize() : 0;
    VALIDATE_STATUS(tx_id, post_req.writeUint64(reply_size));
    if (reply && reply_size > 0) {
        VALIDATE_STATUS(tx_id, post_req.appendFrom(reply, 0, reply_size));
    }

    if (callback->transact(intercept::kPostTransact, post_req, &post_resp) == OK) {
        int32_t post_action = post_resp.readInt32();
        if (post_action == intercept::kActionOverrideReply && reply) {
            result = post_resp.readInt32(); // Read new status
            size_t new_size = post_resp.readUint64();
            reply->setDataSize(0); // Clear original reply
            VALIDATE_STATUS(tx_id, reply->appendFrom(&post_resp, post_resp.dataPosition(), new_size));
        }
    }

    return true; // We handled the flow, even if we just forwarded it
}

// =============================================================================================
// Initialization and Entry Point
// =============================================================================================

bool initialize_hooks() {
    auto maps = lsplt::MapInfo::Scan();

    dev_t binder_dev = 0;
    ino_t binder_ino = 0;
    bool found = false;

    for (const auto &map : maps) {
        if (map.path.ends_with(intercept::kBinderLibName)) {
            binder_dev = map.dev;
            binder_ino = map.inode;
            found = true;
            LOGD("Found libbinder at: %s", map.path.c_str());
            break;
        }
    }

    if (!found) {
        LOGE("Could not find libbinder.so in memory maps.");
        return false;
    }

    // Instantiate Singleton components
    g_interceptor_instance = sp<BinderInterceptor>::make();
    g_stub_instance = sp<BinderStub>::make();

    // Register the ioctl hook with LSPLT
    lsplt::RegisterHook(binder_dev, binder_ino, intercept::kIoctlSymbol.data(),
                        reinterpret_cast<void *>(intercepted_ioctl), reinterpret_cast<void **>(&g_original_ioctl));

    if (!lsplt::CommitHook()) {
        LOGE("lsplt::CommitHook failed.");
        return false;
    }

    LOGI("Binder interception initialized successfully.");
    return true;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
bool entry(void *handle) {
    LOGI("Binder Interceptor library loaded (handle: %p)", handle);
    return initialize_hooks();
}
