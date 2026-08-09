#!/system/bin/sh
# Started late at boot. Injects the interceptor into keystore2 and keeps it
# injected across keystore2 restarts.
MODDIR=${0%/*}

# keystore2 is 64-bit; pick the binaries built for this device's primary ABI.
ABI=$(getprop ro.product.cpu.abi)
INJECT="$MODDIR/$ABI/inject"
LIB="$MODDIR/$ABI/libteesim_keymint.so"
[ -x "$INJECT" ] || chmod 0755 "$INJECT" 2>/dev/null
[ -f "$LIB" ] || exit 0

# keystore2 runs unprivileged and cannot traverse /data/adb (0700). Open the
# traversal (not the listing) so it can read its configuration, and make the
# configuration itself world-readable.
chmod 0711 /data/adb 2>/dev/null
chmod 0755 /data/adb/teesim 2>/dev/null
chmod 0644 /data/adb/teesim/keybox.xml /data/adb/teesim/target.txt 2>/dev/null

# keystore2's pid changes whenever it restarts; re-inject each time a new one
# appears. A fresh keystore2 has no interceptor, so this also recovers the module
# if it is ever killed.
(
  last=""
  while true; do
    pid="$(pidof keystore2)"
    if [ -n "$pid" ] && [ "$pid" != "$last" ]; then
      if "$INJECT" "$pid" "$LIB" entry; then
        last="$pid"
      fi
    fi
    sleep 2
  done
) &
