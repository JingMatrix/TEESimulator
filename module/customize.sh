# Runs at install time under Magisk, KernelSU, or APatch.

# The interceptor is a 64-bit library injected into the keystore daemon, which is 64-bit on every
# supported device; refuse 32-bit-only devices rather than fail silently.
if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x64" ]; then
  abort "! TEESimulator requires a 64-bit device"
fi

# Seed the configuration on first install without clobbering existing files.
mkdir -p /data/adb/teesim
# Adopt a keybox the user already set up for TrickyStore when we have none of our own.
if [ ! -f /data/adb/teesim/keybox.xml ] && [ -f /data/adb/tricky_store/keybox.xml ]; then
  ui_print "- Adopting the keybox from TrickyStore"
  cp /data/adb/tricky_store/keybox.xml /data/adb/teesim/keybox.xml
fi
if [ ! -f /data/adb/teesim/config.json ]; then
  cp "$MODPATH/config.default.json" /data/adb/teesim/config.json

  TARGET_TXT="/data/adb/tricky_store/target.txt"
  if [ ! -f /data/adb/modules/tricky_store/disable ] && [ ! -f /data/adb/modules/tricky_store/update/remove ] && [ -s "$TARGET_TXT" ]; then
    ui_print "- Merging TrickyStore target apps into config"

    CONFIG_JSON="/data/adb/teesim/config.json"
    EXISTING_TMP="/data/local/tmp/.teesim_existing_$$"
    TARGET_TMP="/data/local/tmp/.teesim_target_$$"
    MERGED_TMP="/data/local/tmp/.teesim_merged_$$"
    APPS_JSON="/data/local/tmp/.teesim_apps_$$"

    APPS_START=$(grep -n '"apps"' "$CONFIG_JSON" | head -n1 | cut -d: -f1)
    APPS_END=$(tail -n +"$APPS_START" "$CONFIG_JSON" | grep -n '^[[:space:]]*\]' | head -n1 | cut -d: -f1)
    APPS_END=$((APPS_START + APPS_END - 1))

    > "$EXISTING_TMP"
    sed -n "$((APPS_START+1)),$((APPS_END-1))p" "$CONFIG_JSON" | tr -d '\r' | \
      sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^"//;s/",$//;s/"$//' | \
      grep -v '^$' >> "$EXISTING_TMP"

    > "$TARGET_TMP"
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      pkg=$(printf '%s' "$line" | tr -d '\r' | sed 's/[!?]$//;s/^[[:space:]]*//;s/[[:space:]]*$//')
      [ -z "$pkg" ] && continue
      printf '%s\n' "$pkg" >> "$TARGET_TMP"
    done < "$TARGET_TXT"

    sort -u "$EXISTING_TMP" "$TARGET_TMP" > "$MERGED_TMP"

    > "$APPS_JSON"
    first=1
    while IFS= read -r pkg; do
      [ -z "$pkg" ] && continue
      pkg_esc=$(printf '%s' "$pkg" | sed 's/\\/\\\\/g; s/"/\\"/g')
      if [ "$first" -eq 1 ]; then
        printf '        "%s"' "$pkg_esc" >> "$APPS_JSON"
        first=0
      else
        printf ',\n        "%s"' "$pkg_esc" >> "$APPS_JSON"
      fi
    done < "$MERGED_TMP"
    printf '\n' >> "$APPS_JSON"

    TMP_CONFIG="${CONFIG_JSON}.tmp.$$"
    head -n "$APPS_START" "$CONFIG_JSON" > "$TMP_CONFIG"
    cat "$APPS_JSON" >> "$TMP_CONFIG"
    tail -n +"$APPS_END" "$CONFIG_JSON" >> "$TMP_CONFIG"
    mv -f "$TMP_CONFIG" "$CONFIG_JSON"

    rm -f "$EXISTING_TMP" "$TARGET_TMP" "$MERGED_TMP" "$APPS_JSON"
  fi
fi

# TrickyStore intercepts the same keystore path; running both would double-hook it. Disable it via
# its manager's marker (kept, not deleted, so removing us lets the user re-enable it).
for ts in /data/adb/modules/tricky_store /data/adb/modules_update/tricky_store; do
  if [ -d "$ts" ] && [ ! -f "$ts/disable" ]; then
    ui_print "- Disabling TrickyStore (it hooks the same keystore path)"
    touch "$ts/disable"
  fi
done

# Ship only the ABI this device runs; the other ABI's native libraries are dead weight here.
case "$ARCH" in
  arm64) rm -rf "$MODPATH/x86_64" ;;
  x64) rm -rf "$MODPATH/arm64-v8a" ;;
esac

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/daemon" 0 0 0755
for abi in arm64-v8a x86_64; do
  [ -f "$MODPATH/$abi/inject" ] && set_perm "$MODPATH/$abi/inject" 0 0 0755
done
