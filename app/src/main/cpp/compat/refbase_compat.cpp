#include "refbase_compat.h"
#include "utils/RefBase.h"
#include <atomic>
#include <cstdlib>
#include <cstring> // For memcpy
#include <dlfcn.h>
#include <mutex>
#include <sys/system_properties.h>

namespace android {

// Helper function to get the Android API level at runtime.
// It caches the result for performance.
int32_t get_android_api_level() {
  static std::atomic<int32_t> api_level = -1;
  if (api_level.load(std::memory_order_relaxed) == -1) {
    char sdk_version_str[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.sdk", sdk_version_str) > 0) {
      api_level.store(atoi(sdk_version_str), std::memory_order_relaxed);
    }
  }
  return api_level.load(std::memory_order_relaxed);
}

// Define the function pointer type for the const member function
// RefBase::incStrongRequireStrong.
using incStrongRequireStrong_t = void (RefBase::*)(const void *) const;

// This is the implementation of our compatibility wrapper.
void incStrongFromExisting(const RefBase *ref, const void *id) {
  // Only attempt to use the new function on Android 12 (API 31) or higher.
  if (get_android_api_level() >= 31) {
    static incStrongRequireStrong_t sIncStrongRequireStrong = nullptr;
    static std::once_flag sFlag;

    // Thread-safe, one-time initialization.
    std::call_once(sFlag, []() {
      // Find the symbol in the already loaded libraries.
      // The mangled symbol is _ZNK7android7RefBase22incStrongRequireStrongEPKv
      void *sym = dlsym(RTLD_DEFAULT,
                        "_ZNK7android7RefBase22incStrongRequireStrongEPKv");
      if (sym) {
        // Safely cast the void* symbol to our member function pointer.
        memcpy(&sIncStrongRequireStrong, &sym, sizeof(void *));
      }
    });

    if (sIncStrongRequireStrong) {
      // If the symbol was found, call it as member function.
      (ref->*sIncStrongRequireStrong)(id);
      return; // Success, we are done.
    }
    // If dlsym failed for any reason, we fall through to the old method.
  }

  // Fallback for older Android versions or if dlsym failed.
  // This calls the universally available incStrong method.
  ref->incStrong(id);
}

} // namespace android
