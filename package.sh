#!/usr/bin/env bash
# Build the interceptor for each ABI and assemble a flashable module zip.
#
#   ANDROID_HOME / ANDROID_NDK_HOME   SDK / NDK location
#   ABIS="arm64-v8a x86_64"           ABIs to build (keystore2 is 64-bit)
#   API=29                            min platform level
#
# The build depends on no device — libbinder_ndk/liblog come from the NDK and
# BoringSSL is resolved at runtime — so every ABI cross-builds here.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

ABIS=${ABIS:-"arm64-v8a x86_64"}
API=${API:-29}

NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK:-}}
if [ -z "$NDK" ]; then
  NDK=$(ls -d "${ANDROID_HOME:?set ANDROID_HOME or ANDROID_NDK_HOME}"/ndk/* 2>/dev/null | sort -V | tail -1)
fi
[ -d "$NDK" ] || { echo "NDK not found: $NDK" >&2; exit 1; }

git submodule update --init --recursive --depth 1 >/dev/null 2>&1 || true

BUILD=${BUILD:-$HERE/build}
DIST=${DIST:-$HERE/dist}

# Assemble the flashable module: the scripts and config template plus the built
# binaries under a per-ABI directory. The keybox is a user secret and is never shipped.
STAGE=$BUILD/module
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp module/module.prop module/service.sh module/customize.sh \
   module/sepolicy.rule module/target.txt "$STAGE/"

for ABI in $ABIS; do
  B=$BUILD/$ABI
  cmake -B "$B" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" -DANDROID_PLATFORM="android-$API"
  cmake --build "$B" --target inject teesim_keymint
  mkdir -p "$STAGE/$ABI"
  cp "$B/inject" "$STAGE/$ABI/inject"
  cp "$B/libteesim_keymint.so" "$STAGE/$ABI/libteesim_keymint.so"
done

VER=$(sed -n 's/^version=//p' module/module.prop)
mkdir -p "$DIST"
OUT=$DIST/teesim-$VER.zip
rm -f "$OUT"
( cd "$STAGE" && zip -qr "$OUT" . )
echo "packaged: $OUT ($ABIS)"
