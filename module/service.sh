#!/system/bin/sh
# Started late at boot. Injects the interceptor into the keystore daemon and keeps
# it injected across restarts. Android 12+ uses keystore2 (KeyMint); Android 10/11
# use the legacy keystore, which needs the other library and a different hook.
MODDIR=${0%/*}

# keystore runs unprivileged and cannot traverse /data/adb (0700). Open the
# traversal (not the listing) so it can read its configuration.
chmod 0711 /data/adb 2>/dev/null
chmod 0755 /data/adb/teesim 2>/dev/null
chmod 0644 /data/adb/teesim/keybox.xml /data/adb/teesim/target.txt 2>/dev/null

ABI=$(getprop ro.product.cpu.abi)
API=$(getprop ro.build.version.sdk)
INJECT="$MODDIR/$ABI/inject"
[ -x "$INJECT" ] || chmod 0755 "$INJECT" 2>/dev/null

if [ "$API" -ge 31 ]; then
  PROC=keystore2
  LIB="$MODDIR/$ABI/libteesim_keymint.so"
else
  PROC=keystore
  LIB="$MODDIR/$ABI/libteesim_keystore.so"
  # The legacy hook targets by uid, but keystore cannot read the package list, so
  # resolve the target packages to uids here and hand them over.
  : > /data/adb/teesim/targets.uid
  while IFS= read -r pkg || [ -n "$pkg" ]; do
    case "$pkg" in '' | '#'* | '['*) continue ;; esac
    pkg=${pkg%[?!]}
    uid=$(grep -m1 "^$pkg " /data/system/packages.list | cut -d' ' -f2)
    [ -n "$uid" ] && echo "$uid $pkg" >> /data/adb/teesim/targets.uid
  done < /data/adb/teesim/target.txt
  chmod 0644 /data/adb/teesim/targets.uid
fi

[ -f "$LIB" ] || exit 0

# The daemon's pid changes whenever it restarts; re-inject each time a new one
# appears, which also recovers the module if the daemon is ever killed.
(
  last=""
  while true; do
    pid="$(pidof "$PROC")"
    if [ -n "$pid" ] && [ "$pid" != "$last" ]; then
      if "$INJECT" "$pid" "$LIB" entry; then
        last="$pid"
      fi
    fi
    sleep 2
  done
) &
