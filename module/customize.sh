# Runs at install time under Magisk, KernelSU, or APatch.

# The interceptor is a 64-bit library injected into the keystore daemon, which is 64-bit on every
# supported device; refuse 32-bit-only devices rather than fail silently.
if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x64" ]; then
  abort "! TEESimulator requires a 64-bit device"
fi

# TrickyStore intercepts the same keystore path; running both would double-hook it. Disable it via
# its manager's marker (kept, not deleted, so removing us lets the user re-enable it). A
# TrickyStore that was live on this boot keeps its hook until the keystore daemon restarts, so
# disabling one here is also what rules out the hot install below.
DISABLED_TRICKY_STORE=
for ts in /data/adb/modules/tricky_store /data/adb/modules_update/tricky_store; do
  if [ -d "$ts" ] && [ ! -f "$ts/disable" ]; then
    ui_print "- Disabling TrickyStore (it hooks the same keystore path)"
    touch "$ts/disable"
    DISABLED_TRICKY_STORE=1
  fi
done

# Seed the configuration on first install without clobbering existing files.
mkdir -p /data/adb/teesim
# Adopt a keybox the user already set up for TrickyStore when we have none of our own.
if [ ! -f /data/adb/teesim/keybox.xml ] && [ -f /data/adb/tricky_store/keybox.xml ]; then
  ui_print "- Adopting the keybox from TrickyStore"
  cp /data/adb/tricky_store/keybox.xml /data/adb/teesim/keybox.xml
fi
if [ ! -f /data/adb/teesim/config.json ]; then
  cp "$MODPATH/config.default.json" /data/adb/teesim/config.json
fi

# Ship only the ABI this device runs; the other ABI's native libraries are dead weight here.
case "$ARCH" in
  arm64) rm -rf "$MODPATH/x86_64" ;;
  x64) rm -rf "$MODPATH/arm64-v8a" ;;
esac

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/daemon" 0 0 0755
for abi in arm64-v8a x86_64; do
  [ -f "$MODPATH/$abi/inject" ] && set_perm "$MODPATH/$abi/inject" 0 0 0755
  [ -f "$MODPATH/$abi/teesim-uds" ] && set_perm "$MODPATH/$abi/teesim-uds" 0 0 0755
done

# The stage scripts. A manager runs the one whose name it knows, and they all forward to stage.sh;
# late-load.sh is the one a user runs by hand, to arm the module without rebooting.
for s in stage.sh supervise.sh service.sh late-load.sh hotinstall.sh uninstall.sh; do
  [ -f "$MODPATH/$s" ] && set_perm "$MODPATH/$s" 0 0 0755
done

# Nothing TEESimulator installs waits for a boot stage: it mounts no partition and ships no
# system.prop, and its daemon injects whatever keystore process it finds, so hotinstall.sh can
# apply this build in place. KernelSU is the only manager with that path; elsewhere, and whenever a
# live TrickyStore has to be rebooted out of the keystore daemon first, the module is armed by the
# next boot — or by late-load.sh, run by hand.
if [ "$KSU" ] && [ -z "$DISABLED_TRICKY_STORE" ]; then
  ui_print "- Applying without a reboot"
  export MODULE_HOT_INSTALL_REQUEST=true
  export MODULE_HOT_RUN_SCRIPT=hotinstall.sh
elif [ "$DISABLED_TRICKY_STORE" ]; then
  ui_print "- Reboot to apply: TrickyStore was active and keeps its keystore hook until then"
else
  ui_print "- Reboot to apply, or run late-load.sh from the module directory"
fi
