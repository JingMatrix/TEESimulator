// Injection entry point for the legacy keystore interceptor (Android 10/11).
//
// The injector loads this into the keystore daemon and calls entry(). We build the
// TA from the keybox, resolve the configured target packages to their uids, install
// the libbinder ioctl hook, and register the app-facing keystore service so its
// transactions are handed to our handler.

#include <binder/IServiceManager.h>
#include <binder/Parcel.h>

#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include "logging.hpp"
#include "teesim_km.h"

using namespace android;
using TransactionHandler =
    std::function<bool(uint32_t code, const Parcel& data, Parcel* reply, status_t& result)>;

// binder_interceptor.cpp
bool teesim_intercept_service(const sp<IBinder>& service, TransactionHandler handler);
bool teesim_install_binder_hook();
// keystore_router.cpp
extern "C" void teesim_ks_set_ta(Ta* ta);
extern "C" void teesim_ks_add_target(int uid, const char* pkg);
extern "C" bool teesim_ks_handle(uint32_t code, const Parcel& data, Parcel* reply, status_t& result);

namespace {

constexpr const char* kKeyboxPath = "/data/adb/teesim/keybox.xml";

std::string ReadFile(const char* path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// The unprivileged keystore cannot read the system package list, so service.sh
// resolves the target packages to uids as root and writes them here, one
// "<uid> <package>" per line, for us to register.
void RegisterTargets() {
  std::stringstream ss(ReadFile("/data/adb/teesim/targets.uid"));
  std::string line;
  while (std::getline(ss, line)) {
    std::istringstream ls(line);
    int uid = 0;
    std::string pkg;
    if (ls >> uid >> pkg) {
      teesim_ks_add_target(uid, pkg.c_str());
      LOGI("keystore: target uid %d -> %s", uid, pkg.c_str());
    }
  }
}

}  // namespace

extern "C" [[gnu::visibility("default")]] bool entry(void* /*handle*/) {
  LOGI("keystore interceptor loading");

  std::string keybox = ReadFile(kKeyboxPath);
  if (keybox.empty()) {
    LOGE("keystore: no keybox at %s", kKeyboxPath);
    return false;
  }
  Ta* ta = teesim_km_init(reinterpret_cast<const uint8_t*>(keybox.data()), keybox.size());
  if (!ta) {
    LOGE("keystore: TA init failed (bad keybox?)");
    return false;
  }
  teesim_ks_set_ta(ta);
  RegisterTargets();

  if (!teesim_install_binder_hook()) {
    LOGE("keystore: failed to install the binder hook");
    return false;
  }
  sp<IBinder> service = defaultServiceManager()->checkService(String16("android.security.keystore"));
  if (service == nullptr) {
    LOGE("keystore: android.security.keystore not found");
    return false;
  }
  bool ok = teesim_intercept_service(service, &teesim_ks_handle);
  LOGI("keystore interceptor installed=%d", ok);
  return ok;
}
