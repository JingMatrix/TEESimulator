// Server-side interception of the legacy keystore service (Android 10/11).
//
// Android 10/11 have no keystore2/KeyMint. Apps talk to the `keystore` daemon over
// its IKeystoreService binder, and the daemon reaches a Keymaster HAL beneath it.
// Rather than follow that HIDL path we intercept the app-facing service directly:
// injected into keystore, we PLT-hook ioctl on libbinder, watch the incoming
// BR_TRANSACTIONs, and for the registered keystore binder rewrite the target to a
// local stub. The stub hands the transaction to an in-process handler that can
// answer it (from the TA) or let it fall through to the real service.

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>

#include <linux/android/binder.h>
#include <sys/ioctl.h>

#include <atomic>
#include <cstdarg>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <thread>

#include "logging.hpp"
#include "lsplt.hpp"

using namespace android;

namespace {

constexpr uint32_t kStubCode = 0xdeadbeef;
constexpr std::string_view kBinderLibName = "/libbinder.so";

// A handler answers an intercepted transaction. Returning true means it produced
// the reply; false forwards the call to the real service.
using TransactionHandler =
    std::function<bool(uint32_t code, const Parcel& data, Parcel* reply, status_t& result)>;

int (*g_original_ioctl)(int fd, int request, ...) = nullptr;
std::atomic<uint64_t> g_tx_counter = 0;

// Per-thread hand-off from the ioctl hook to the stub's onTransact.
struct TxInfo {
  uint32_t code = 0;
  wp<BBinder> target;
};
std::mutex g_ctx_mutex;
std::map<std::thread::id, std::queue<TxInfo>> g_ctx_map;

// Registry of intercepted service binders and their handlers.
std::shared_mutex g_registry_mutex;
std::map<wp<IBinder>, TransactionHandler> g_registry;

bool IsIntercepted(const wp<BBinder>& target) {
  std::shared_lock lock(g_registry_mutex);
  return g_registry.find(target) != g_registry.end();
}

TransactionHandler HandlerFor(const sp<BBinder>& target) {
  std::shared_lock lock(g_registry_mutex);
  auto it = g_registry.find(wp<IBinder>(target));
  return it == g_registry.end() ? nullptr : it->second;
}

// The stub that intercepted transactions are redirected to. It recovers the
// original target and code from the thread hand-off and runs the handler.
class BinderStub : public BBinder {
 public:
  const String16& getInterfaceDescriptor() const override {
    static const String16 kDescriptor("org.matrix.TEESimulator.BinderStub");
    return kDescriptor;
  }

 protected:
  status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override {
    if (code != kStubCode) return UNKNOWN_TRANSACTION;

    TxInfo info;
    {
      std::lock_guard<std::mutex> lock(g_ctx_mutex);
      auto it = g_ctx_map.find(std::this_thread::get_id());
      if (it == g_ctx_map.end() || it->second.empty()) return UNKNOWN_TRANSACTION;
      info = std::move(it->second.front());
      it->second.pop();
      if (it->second.empty()) g_ctx_map.erase(it);
    }

    sp<BBinder> target = info.target.promote();
    if (!target) return DEAD_OBJECT;

    if (TransactionHandler handler = HandlerFor(target)) {
      status_t result = OK;
      if (handler(info.code, data, reply, result)) return result;
    }
    return target->transact(info.code, data, reply, flags);
  }
};

sp<BinderStub> g_stub = nullptr;

// If a transaction targets a registered binder, redirect it to the stub and stash
// the original target/code for the stub to pick up on this thread.
void InspectAndRewrite(binder_transaction_data* txn) {
  if (!txn || txn->target.ptr == 0 || txn->code == kStubCode) return;

  auto* weak = reinterpret_cast<RefBase::weakref_type*>(txn->target.ptr);
  if (!weak || !weak->attemptIncStrong(nullptr)) return;
  auto* binder = reinterpret_cast<BBinder*>(txn->cookie);
  wp<BBinder> target = binder;

  bool hijack = IsIntercepted(target);
  if (hijack) {
    TxInfo info{txn->code, target};
    txn->target.ptr = reinterpret_cast<uintptr_t>(g_stub->getWeakRefs());
    txn->cookie = reinterpret_cast<uintptr_t>(g_stub.get());
    txn->code = kStubCode;
    std::lock_guard<std::mutex> lock(g_ctx_mutex);
    g_ctx_map[std::this_thread::get_id()].push(std::move(info));
  }
  binder->decStrong(nullptr);
}

// Walk the driver-to-userspace command buffer and inspect each BR_TRANSACTION.
void ProcessReadBuffer(const binder_write_read& bwr) {
  uintptr_t ptr = bwr.read_buffer;
  uintptr_t end = ptr + bwr.read_consumed;
  while (ptr + sizeof(uint32_t) <= end) {
    uint32_t cmd = *reinterpret_cast<const uint32_t*>(ptr);
    ptr += sizeof(uint32_t);
    size_t size = _IOC_SIZE(cmd);
    if (ptr + size > end) break;
    if (cmd == BR_TRANSACTION) {
      InspectAndRewrite(reinterpret_cast<binder_transaction_data*>(ptr));
    } else if (cmd == BR_TRANSACTION_SEC_CTX) {
      InspectAndRewrite(&reinterpret_cast<binder_transaction_data_secctx*>(ptr)->transaction_data);
    }
    ptr += size;
  }
}

int intercepted_ioctl(int fd, int request, ...) {
  va_list ap;
  va_start(ap, request);
  void* arg = va_arg(ap, void*);
  va_end(ap);

  int result = g_original_ioctl(fd, request, arg);
  if (result >= 0 && request == BINDER_WRITE_READ && arg) {
    const auto* bwr = static_cast<const binder_write_read*>(arg);
    if (bwr->read_consumed > 0) ProcessReadBuffer(*bwr);
  }
  return result;
}

}  // namespace

// Register an in-process handler for a local service binder.
bool teesim_intercept_service(const sp<IBinder>& service, TransactionHandler handler) {
  if (!service || service->localBinder() == nullptr) {
    LOGE("keystore: refusing to intercept a non-local binder");
    return false;
  }
  std::unique_lock lock(g_registry_mutex);
  g_registry[wp<IBinder>(service)] = std::move(handler);
  LOGI("keystore: intercepting service binder %p", service.get());
  return true;
}

// Install the ioctl hook on libbinder. Returns false if libbinder is not mapped.
bool teesim_install_binder_hook() {
  dev_t dev = 0;
  ino_t ino = 0;
  bool found = false;
  for (const auto& m : lsplt::MapInfo::Scan()) {
    if (m.path.ends_with(kBinderLibName)) {
      dev = m.dev;
      ino = m.inode;
      found = true;
      break;
    }
  }
  if (!found) {
    LOGE("keystore: libbinder.so not found in maps");
    return false;
  }
  g_stub = sp<BinderStub>::make();
  lsplt::RegisterHook(dev, ino, "ioctl", reinterpret_cast<void*>(intercepted_ioctl),
                      reinterpret_cast<void**>(&g_original_ioctl));
  lsplt::CommitHook();
  return g_original_ioctl != nullptr;
}
