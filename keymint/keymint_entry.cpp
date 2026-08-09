// Injection entry point for the KeyMint interceptor (Android 12+).
//
// The daemon injects this library into keystore2 and calls entry(). We install
// the AIBinder_transact hook in an unconfigured, forward-everything state and
// start the control server; the daemon then connects over @teesim and pushes the
// resolved profile set. Nothing is read from disk here — the lib is a pure
// engine driven entirely by control-channel pushes.

#include "control.h"
#include "logging.hpp"

// keymint_hook.cpp
extern "C" bool teesim_hook_install();

extern "C" [[gnu::visibility("default")]] bool entry(void* /*handle*/) {
  LOGI("TEESimulator KeyMint interceptor loading");
  teesim_control_start();
  bool ok = teesim_hook_install();
  LOGI("TEESimulator KeyMint interceptor installed=%d (awaiting config push)", ok);
  return ok;
}
