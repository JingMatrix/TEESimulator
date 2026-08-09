#!/system/bin/sh
# Started late at boot. The Kotlin control daemon does the real work — it harvests
# the device's attestation parameters, resolves config.json into per-profile
# settings, injects the interceptor into keystore/keystore2, and pushes the resolved
# config over the control socket, re-injecting and re-pushing as things change. This
# script only launches the daemon and respawns it if it ever exits.
MODDIR=${0%/*}

# admin.token is the WebUI's key-management credential; keep it root-only.
chmod 0600 /data/adb/teesim/admin.token 2>/dev/null

while true; do
  "$MODDIR/daemon" "$MODDIR"
  sleep 2
done &
