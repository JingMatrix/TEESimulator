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
#include <android/binder_status.h>

#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "logging.hpp"
#include "lsplt.hpp"

using aidl::android::hardware::security::keymint::IKeyMintDevice;

// Implemented in keymint_router.cpp.
extern "C" AIBinder* teesim_router_new_device(int32_t security_level, AIBinder* real_binder);
// True if the calling uid belongs to a live target profile (keymint_router.cpp).
extern "C" bool teesim_is_target_uid(int32_t uid);

namespace {

binder_status_t (*real_transact)(AIBinder*, transaction_code_t, AParcel**, AParcel**,
                                 binder_flags_t) = nullptr;

// Marks the current thread as forwarding into the real HAL, so we let those
// transactions pass straight through.
thread_local bool tls_forwarding = false;

std::mutex g_mu;
// Real KeyMint proxy -> our local device wrapping it. A nullptr value is a NEGATIVE cache ("do not
// wrap this proxy", i.e. a SOFTWARE-level km_compat device) so we neither re-probe its
// getHardwareInfo nor rebuild a device on every transact. Keyed on the raw proxy pointer, which is
// safe because keystore2 caches its per-level KeyMint devices for the process lifetime, so the
// pointer is stable and never reallocated (the negative cache relies on this too).
std::map<AIBinder*, AIBinder*> g_local_for_proxy;

// Our own local devices (the non-null values of g_local_for_proxy). IsKeyMintProxy matches any local
// IKeyMintDevice by descriptor, and our own TeesimKeyMintDevice is one, so IsKeyMintProxy excludes
// anything in this set. (Redirect dispatches our device through real_transact — the unhooked LSPlt
// backup — so it never re-enters the hook; forwarding recursion is prevented by tls_forwarding, not
// this set. This is a guard against any other caller transacting our device through the hooked symbol.)
//
// Guarded by a SEPARATE mutex, not g_mu: LocalFor holds g_mu across teesim_router_new_device, which
// makes a blocking getHardwareInfo IPC into the real HAL, while IsOurDevice runs on the transact hot
// path — one shared lock would stall every handled transact behind device construction. Lock order is
// always g_mu -> g_our_mu (IsOurDevice takes g_our_mu alone; LocalFor takes g_mu, then g_our_mu).
std::mutex g_our_mu;
std::set<AIBinder*> g_our_devices;

// True if `binder` is a TeesimKeyMintDevice we created.
bool IsOurDevice(AIBinder* binder) {
  std::lock_guard<std::mutex> lk(g_our_mu);
  return g_our_devices.count(binder) != 0;
}

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

// Identity check for the KeyMint binder keystore2 transacts. We match on the class descriptor alone
// and do not require AIBinder_isRemote, so we catch KeyMint whether it is remote or in-process:
//
//   - Native KeyMint HAL: keystore2's TrustedEnvironment/StrongBox proxy is a remote binder.
//   - Legacy Keymaster (keymaster@4.x) backend: keystore2 has no native KeyMint, so per security level
//     it holds an in-process km_compat IKeyMintDevice (getKeyMintDevice) — stored directly (keymaster
//     4.0/4.1) or behind a BacklevelKeyMintWrapper (downlevel). Either way the binder that reaches
//     AIBinder_transact is a local proxy (isRemote==false).
//
// The SOFTWARE level is excluded by level, not here: keystore2 serves SecurityLevel::SOFTWARE from an
// in-process km_compat device on every device, and teesim_router_new_device returns nullptr for it
// (LocalFor caches that), so the software leg is never wrapped. See that function.
//
// The descriptor also matches our own local TeesimKeyMintDevice, so we exclude it (IsOurDevice). The
// descriptor is compared first, so the g_our_mu lookup runs only for actual IKeyMintDevice binders.
bool IsKeyMintProxy(AIBinder* binder) {
  const AIBinder_Class* clazz = AIBinder_getClass(binder);
  if (!clazz) return false;
  const char* desc = AIBinder_Class_getDescriptor(clazz);
  if (!desc || std::strcmp(desc, IKeyMintDevice::descriptor) != 0) return false;
  return !IsOurDevice(binder);
}

// The framework RKP front-end keystore2 asks for a remote-provisioned attestation key. keystore2
// resolves it by calling IRemoteProvisioning.getRegistration on this binder; failing that transact
// makes keystore2 fall back to "no attest key" (get_attest_key_info -> Ok(None)) on a hybrid device,
// so it appends no real-hardware certificate chain to the key we mint.
bool IsRkpProvisioning(AIBinder* binder) {
  if (!AIBinder_isRemote(binder)) return false;
  const AIBinder_Class* clazz = AIBinder_getClass(binder);
  if (!clazz) return false;
  const char* desc = AIBinder_Class_getDescriptor(clazz);
  return desc && std::strcmp(desc, "android.security.rkp.IRemoteProvisioning") == 0;
}

// Whether a security level's rkp_only property is set. On such a level keystore2 has no batch key to
// fall back to, so denying its RKP lookup makes generateKey fail outright (get_attest_key_info returns
// Err instead of Ok(None)); there we must let the lookup through. We only ever READ the property — a
// global write would be an obvious detection point.
bool PropIsRkpOnly(const char* name) {
  char buf[PROP_VALUE_MAX] = {0};
  int n = __system_property_get(name, buf);
  return n > 0 && (std::strcmp(buf, "true") == 0 || std::strcmp(buf, "1") == 0);
}

// Allocator for AParcel_readString: `length` includes the null terminator, or is -1 for a null string.
bool RkpStringAllocator(void* string_data, int32_t length, char** buffer) {
  char** out = static_cast<char**>(string_data);
  if (length < 0) {
    *out = nullptr;
    *buffer = nullptr;
    return true;
  }
  *out = static_cast<char*>(malloc(length));
  if (*out == nullptr) return false;
  *buffer = *out;
  return true;
}

// Which security level a getRegistration transact targets, read from its first argument — the
// IRemotelyProvisionedComponent name ("strongbox" for StrongBox, "default" for TE). The interface
// header size is measured from a throwaway prepared transaction on the same binder, so no wire format
// is hardcoded; the input parcel's read position is saved and restored. Defaults to TE if unreadable.
bool GetRegIsStrongBox(AIBinder* binder, AParcel* in) {
  AParcel* probe = nullptr;
  if (AIBinder_prepareTransaction(binder, &probe) != STATUS_OK) return false;
  int32_t header = AParcel_getDataSize(probe);  // args begin past the interface header (cf. Redirect)
  AParcel_delete(probe);

  int32_t saved = AParcel_getDataPosition(in);
  if (AParcel_setDataPosition(in, header) != STATUS_OK) return false;
  char* name = nullptr;
  bool strongbox = false;
  if (AParcel_readString(in, &name, RkpStringAllocator) == STATUS_OK && name != nullptr) {
    strongbox = std::strcmp(name, "strongbox") == 0;
  }
  free(name);
  AParcel_setDataPosition(in, saved);
  return strongbox;
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
  g_local_for_proxy[proxy] = local;  // may be nullptr (SOFTWARE): negative cache, do not re-probe
  if (local) {
    // Record our device so the relaxed IsKeyMintProxy never re-wraps it. We already hold g_mu; lock
    // order is g_mu -> g_our_mu. Never insert nullptr (a SOFTWARE proxy yields local==nullptr): the
    // "g_our_devices == our real devices" invariant must hold.
    std::lock_guard<std::mutex> lk(g_our_mu);
    g_our_devices.insert(local);
  }
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
  if (!tls_forwarding && in && *in) {
    // Deny a target app's remote-provisioning lookup so keystore2 attaches no real attest key. The
    // RKP resolution runs on this same binder thread (a current-thread tokio runtime block_on), while
    // keystore2 is still serving the app's generateKey, so getCallingUid is the app's uid. The gate is
    // per security level: keystore2 reads .tee.rkp_only for a TE request and .strongbox.rkp_only for a
    // StrongBox one, and denying an rkp-only level fails the key instead of falling back — so pick the
    // property matching this getRegistration's target (its irpcName) rather than the TEE one alone.
    if (IsRkpProvisioning(binder)) {
      int32_t uid = static_cast<int32_t>(AIBinder_getCallingUid());
      if (teesim_is_target_uid(uid)) {
        bool strongbox = GetRegIsStrongBox(binder, *in);
        const char* prop = strongbox ? "remote_provisioning.strongbox.rkp_only"
                                      : "remote_provisioning.tee.rkp_only";
        if (PropIsRkpOnly(prop)) {
          LOGI("RKP: NOT denying %s getRegistration for target uid=%d (%s set; denial would fail key "
               "generation on an rkp-only level)",
               strongbox ? "strongbox" : "TE", uid, prop);
        } else {
          LOGI("RKP: denying %s IRemoteProvisioning transact code=%u for target uid=%d "
               "(keystore2 will append no real attest-key chain; our generation stays keybox-rooted)",
               strongbox ? "strongbox" : "TE", code, uid);
          AParcel_delete(*in);  // honour AIBinder_transact's ownership of the input parcel
          *in = nullptr;
          return STATUS_FAILED_TRANSACTION;  // -> Rust `?` -> get_attest_key_info Ok(None) on hybrid
        }
      }
    }
    if (IsHandled(code) && IsKeyMintProxy(binder)) {
      AIBinder* local = LocalFor(binder);
      if (local) return Redirect(local, code, in, out, flags, binder);
      // local == nullptr: a SOFTWARE-level proxy we deliberately do not wrap; fall through to
      // real_transact so keystore2's own software-key path runs untouched.
    }
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
    if (real_transact != nullptr) {
      LOGI("hook: AIBinder_transact patched in the main executable (%s)", exe.c_str());
      return true;
    }
  }
  register_and_commit(/*exe_only=*/false);
  LOGI("hook: AIBinder_transact %s after full ELF scan",
       real_transact != nullptr ? "patched" : "not found (no importer)");
  return real_transact != nullptr;
}
