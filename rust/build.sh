#!/usr/bin/env bash
# Build libteesim_km for Android against the platform BoringSSL.
#
# The crate links the device's libcrypto.so dynamically, so the build needs
# BoringSSL headers (openssl-sys bindgens the FFI from them) and a libcrypto.so
# of the target ABI to satisfy the linker. Configure via environment:
#   NDK_HOME   Android NDK (default: newest under $ANDROID_HOME/ndk)
#   ABI        Android ABI (default: arm64-v8a)
#   API        platform level (default: 34)
#   BORINGSSL  BoringSSL source dir with include/ (cloned if unset/missing)
#   LIBDIR     dir with libcrypto.so for $ABI (pulled from $DEVICE if unset)
#   DEVICE     adb serial to pull libcrypto.so from
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ABI="${ABI:-arm64-v8a}"
API="${API:-34}"

case "$ABI" in
  arm64-v8a)   TRIPLE=aarch64-linux-android;   DEVLIB=/system/lib64 ;;
  armeabi-v7a) TRIPLE=armv7-linux-androideabi; DEVLIB=/system/lib ;;
  x86_64)      TRIPLE=x86_64-linux-android;    DEVLIB=/system/lib64 ;;
  x86)         TRIPLE=i686-linux-android;      DEVLIB=/system/lib ;;
  *) echo "unknown ABI: $ABI" >&2; exit 1 ;;
esac
ENVPREFIX="$(echo "$TRIPLE" | tr '[:lower:]-' '[:upper:]_')"

if [ -z "${NDK_HOME:-}" ]; then
  NDK_HOME="$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "$NDK_HOME" ] || { echo "NDK not found; set NDK_HOME" >&2; exit 1; }
export ANDROID_NDK_HOME="$NDK_HOME" ANDROID_NDK="$NDK_HOME"

# Adapt the reference BoringSSL backend to build under Cargo (openssl-sys) rather
# than Soong (bssl-sys). Applied to the submodule working tree, idempotently.
PATCH="$HERE/patches/kmr-crypto-boring.patch"
if git -C "$ROOT/third_party/keymint" apply -p1 --reverse --check "$PATCH" 2>/dev/null; then
  :
else
  git -C "$ROOT/third_party/keymint" apply -p1 "$PATCH"
fi

BORINGSSL="${BORINGSSL:-$HERE/.boringssl-src}"
if [ ! -f "$BORINGSSL/include/openssl/base.h" ]; then
  git clone --depth 1 https://boringssl.googlesource.com/boringssl "$BORINGSSL"
fi

LIBDIR="${LIBDIR:-$HERE/.dynlibs/$ABI}"
if [ ! -f "$LIBDIR/libcrypto.so" ]; then
  [ -n "${DEVICE:-}" ] || { echo "no libcrypto.so and no DEVICE to pull from" >&2; exit 1; }
  mkdir -p "$LIBDIR"
  adb connect "$DEVICE" >/dev/null 2>&1 || true
  adb -s "$DEVICE" pull "$DEVLIB/libcrypto.so" "$LIBDIR/libcrypto.so"
fi

if [ -z "${LIBCLANG_PATH:-}" ]; then
  for p in /usr/lib /usr/lib64 /usr/lib/llvm/lib /usr/lib/x86_64-linux-gnu; do
    [ -e "$p/libclang.so" ] && export LIBCLANG_PATH="$p" && break
  done
fi

export OPENSSL_NO_VENDOR=1
export "${ENVPREFIX}_OPENSSL_INCLUDE_DIR=$BORINGSSL/include"
export "${ENVPREFIX}_OPENSSL_LIB_DIR=$LIBDIR"
export "${ENVPREFIX}_OPENSSL_STATIC=0"
export "${ENVPREFIX}_OPENSSL_LIBS=crypto"

cd "$HERE"
cargo ndk -t "$ABI" --platform "$API" --bindgen build --release -p teesim-km

echo "Output: $HERE/target/$TRIPLE/release/libteesim_km.{so,a}"
