#!/usr/bin/env bash
# Build both interceptors for each ABI and assemble a flashable module zip.
#
#   ANDROID_HOME / ANDROID_NDK_HOME   SDK / NDK location
#   ABIS="arm64-v8a x86_64"           ABIs to build (the daemons are 64-bit)
#   API=29                            min platform level
#
# keystore2 (Android 12+) resolves BoringSSL from its own process, so its library
# links only a stub. The legacy keystore (Android 10/11) has an older libcrypto,
# so its library bundles a modern static BoringSSL built from the submodule. The
# build needs no device.
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
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"

git submodule update --init --recursive --depth 1 >/dev/null 2>&1 || true

BUILD=${BUILD:-$HERE/build}
DIST=${DIST:-$HERE/dist}

STAGE=$BUILD/module
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp module/module.prop module/service.sh module/customize.sh \
   module/sepolicy.rule module/target.txt "$STAGE/"
cp -r module/webroot "$STAGE/"

for ABI in $ABIS; do
  # keystore2 interceptor (+ the injector), resolving BoringSSL at runtime.
  B2=$BUILD/$ABI/keystore2
  cmake -B "$B2" -G Ninja -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" -DANDROID_PLATFORM="android-$API"
  cmake --build "$B2" --target inject teesim_keymint

  # A static BoringSSL for the legacy interceptor to bundle (cached across runs).
  BSSL=$BUILD/boringssl/$ABI
  if [ ! -f "$BSSL/libcrypto.a" ]; then
    cmake -B "$BSSL" -G Ninja -S third_party/boringssl \
      -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" -DANDROID_ABI="$ABI" \
      -DANDROID_PLATFORM="android-$API" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
    ninja -C "$BSSL" crypto
  fi

  # keystore interceptor, bundling that static BoringSSL.
  B1=$BUILD/$ABI/keystore
  cmake -B "$B1" -G Ninja -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" -DANDROID_PLATFORM="android-$API" \
    -DCRYPTO_STATIC_LIB="$BSSL/libcrypto.a"
  cmake --build "$B1" --target teesim_keystore

  mkdir -p "$STAGE/$ABI"
  cp "$B2/inject" "$STAGE/$ABI/inject"
  cp "$B2/libteesim_keymint.so" "$STAGE/$ABI/libteesim_keymint.so"
  cp "$B1/libteesim_keystore.so" "$STAGE/$ABI/libteesim_keystore.so"
done

VER=$(sed -n 's/^version=//p' module/module.prop)
mkdir -p "$DIST"
OUT=$DIST/teesim-$VER.zip
rm -f "$OUT"
( cd "$STAGE" && zip -qr "$OUT" . )
echo "packaged: $OUT ($ABIS)"
