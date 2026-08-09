// Interceptor that redirects keystore2's KeyMint transactions to our local
// binder.
//
// keystore2 resolves and caches the KeyMint proxy at boot, before we are
// injected, so we cannot redirect at resolution time. Instead we PLT-hook
// AIBinder_transact: for a transaction on the real KeyMint proxy whose code is
// one we handle, we copy the request into a parcel bound to our local binder and
// dispatch it there. The local binder itself decides, per request, whether to
// simulate or forward to the real HAL, so this hook is deliberately dumb.

#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>

#include <unistd.h>

#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "lsplt.hpp"

using aidl::android::hardware::security::keymint::IKeyMintDevice;

// Implemented in keymint_router.cpp.
extern "C" AIBinder* teesim_router_new_device(int32_t security_level, AIBinder* real_binder);

namespace {

binder_status_t (*real_transact)(AIBinder*, transaction_code_t, AParcel**, AParcel**,
                                 binder_flags_t) = nullptr;

// Marks the current thread as forwarding into the real HAL, so we let those
// transactions pass straight through.
thread_local bool tls_forwarding = false;

std::mutex g_mu;
// Real KeyMint proxy -> our local device wrapping it.
std::map<AIBinder*, AIBinder*> g_local_for_proxy;

bool IsHandled(transaction_code_t code) {
  switch (code) {
    case 3:   // generateKey
    case 4:   // importKey
    case 5:   // importWrappedKey
    case 6:   // upgradeKey
    case 7:   // deleteKey
    case 10:  // begin
    case 13:  // convertStorageKeyToEphemeral
    case 14:  // getKeyCharacteristics
      return true;
    default:
      return false;
  }
}

bool IsKeyMintProxy(AIBinder* binder) {
  if (!AIBinder_isRemote(binder)) return false;
  const AIBinder_Class* clazz = AIBinder_getClass(binder);
  if (!clazz) return false;
  const char* desc = AIBinder_Class_getDescriptor(clazz);
  return desc && std::strcmp(desc, IKeyMintDevice::descriptor) == 0;
}

// Return (creating if needed) the local device that wraps `proxy`.
AIBinder* LocalFor(AIBinder* proxy) {
  std::lock_guard<std::mutex> lk(g_mu);
  auto it = g_local_for_proxy.find(proxy);
  if (it != g_local_for_proxy.end()) return it->second;
  // teesim_router_new_device derives this proxy's real security level from the
  // wrapped HAL's getHardwareInfo(); the value passed here is only the fallback
  // used if that query fails.
  AIBinder* local = teesim_router_new_device(1 /* fallback: TRUSTED_ENVIRONMENT */, proxy);
  g_local_for_proxy[proxy] = local;
  return local;
}

binder_status_t Redirect(AIBinder* local, transaction_code_t code, AParcel** in, AParcel** out,
                         binder_flags_t flags, AIBinder* proxy) {
  AParcel* my_in = nullptr;
  if (AIBinder_prepareTransaction(local, &my_in) != STATUS_OK) {
    return real_transact(proxy, code, in, out, flags);
  }
  int32_t hdr = AParcel_getDataSize(my_in);
  int32_t total = AParcel_getDataSize(*in);
  if (total < hdr || AParcel_appendFrom(*in, my_in, hdr, total - hdr) != STATUS_OK) {
    AParcel_delete(my_in);
    return real_transact(proxy, code, in, out, flags);
  }
  binder_status_t r = real_transact(local, code, &my_in, out, flags);  // consumes my_in
  AParcel_delete(*in);  // match AIBinder_transact's ownership contract
  *in = nullptr;
  return r;
}

binder_status_t HookedTransact(AIBinder* binder, transaction_code_t code, AParcel** in,
                               AParcel** out, binder_flags_t flags) {
  if (!tls_forwarding && in && *in && IsHandled(code) && IsKeyMintProxy(binder)) {
    AIBinder* local = LocalFor(binder);
    if (local) return Redirect(local, code, in, out, flags, binder);
  }
  return real_transact(binder, code, in, out, flags);
}

}  // namespace

extern "C" void teesim_hook_set_forwarding(bool forwarding) { tls_forwarding = forwarding; }

// Only hook real ELF modules: the main executable and shared libraries. Feeding
// LSPlt a non-ELF mapping (fonts, dex, oat, apk) makes its ELF parser fault.
bool IsHookableElf(const std::string& path, const std::string& exe) {
  if (path == exe) return true;
  if (path.size() < 3) return false;
  return path.compare(path.size() - 3, 3, ".so") == 0;
}

extern "C" bool teesim_hook_install() {
  char exe_buf[512] = {0};
  ssize_t n = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
  std::string exe = n > 0 ? std::string(exe_buf, n) : std::string();

  const auto maps = lsplt::MapInfo::Scan();

  // Register the AIBinder_transact hook across a chosen set of modules and commit. `exe_only`
  // limits it to the main executable; otherwise every ELF module (main exe + .so) is probed.
  auto register_and_commit = [&](bool exe_only) {
    std::set<std::pair<dev_t, ino_t>> seen;
    for (const auto& m : maps) {
      if (m.path.empty() || m.inode == 0) continue;
      if (exe_only ? (m.path != exe) : !IsHookableElf(m.path, exe)) continue;
      if (!seen.insert({m.dev, m.inode}).second) continue;
      lsplt::RegisterHook(m.dev, m.inode, "AIBinder_transact",
                          reinterpret_cast<void*>(HookedTransact),
                          reinterpret_cast<void**>(&real_transact));
    }
    // CommitHook returns false when a probed module doesn't import the symbol, which is
    // expected; success is that the caller's slot was patched (backup set).
    lsplt::CommitHook();
  };

  // The transaction we intercept — keystore2 forwarding to the real KeyMint — is issued from
  // the main executable, which is where AIBinder_transact is imported (keystore2's binder client
  // is linked into the binary). So probe just the executable's PLT first: this avoids scanning
  // (and having LSPlt warn about) every unrelated .so. Only if the importer isn't the executable
  // on some build do we widen to a full ELF scan, so coverage is never lost.
  if (!exe.empty()) {
    register_and_commit(/*exe_only=*/true);
    if (real_transact != nullptr) return true;
  }
  register_and_commit(/*exe_only=*/false);
  return real_transact != nullptr;
}
