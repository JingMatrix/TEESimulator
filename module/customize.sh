# Runs at install time under Magisk, KernelSU, or APatch.

# The interceptor is a 64-bit library injected into keystore2, which is 64-bit on
# every supported device; refuse 32-bit-only devices rather than fail silently.
if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x64" ]; then
  abort "! TEESimulator requires a 64-bit device"
fi

# Seed the configuration on first install without clobbering existing files.
mkdir -p /data/adb/teesim
if [ ! -f /data/adb/teesim/keybox.xml ] && [ -f "$MODPATH/keybox.xml" ]; then
  cp "$MODPATH/keybox.xml" /data/adb/teesim/keybox.xml
fi
if [ ! -f /data/adb/teesim/config.json ]; then
  cp "$MODPATH/config.default.json" /data/adb/teesim/config.json
fi

# The keybox is shipped as a template only; the module dir is world-readable, so
# do not leave a real one lying in it.
rm -f "$MODPATH/keybox.xml"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/daemon" 0 0 0755
for abi in arm64-v8a x86_64; do
  [ -f "$MODPATH/$abi/inject" ] && set_perm "$MODPATH/$abi/inject" 0 0 0755
done
