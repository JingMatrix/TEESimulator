#!/system/bin/sh
# Started late at boot. The Kotlin control daemon does the real work — it harvests
# the device's attestation parameters, resolves config.json into per-profile
# settings, injects the interceptor into keystore/keystore2, and pushes the resolved
# config over the control socket, re-injecting and re-pushing as things change. This
# script only launches the daemon and respawns it if it ever exits.
MODDIR=${0%/*}

# admin.token is the WebUI's key-management credential; keep it root-only. The whole data dir holds
# the token and the admin socket, so keep it 0700 too — the socket is then unreachable to other apps.
chmod 0700 /data/adb/teesim 2>/dev/null
chmod 0600 /data/adb/teesim/admin.token 2>/dev/null

# Stage the WebUI's admin-socket client at a fixed, root-only path, so the WebUI can invoke it without
# knowing the module's runtime path or the device ABI. Only the device's own ABI dir survives install,
# so the glob matches one file; refreshed every boot so a module update always stages the current one.
for f in "$MODDIR"/*/teesim-uds; do
  if [ -f "$f" ]; then
    cp "$f" /data/adb/teesim/teesim-uds && chmod 0700 /data/adb/teesim/teesim-uds
    break
  fi
done

while true; do
  "$MODDIR/daemon" "$MODDIR"
  sleep 2
done &
