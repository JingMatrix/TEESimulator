#!/usr/bin/env bash
# Build libteesim_km.a for one Android ABI.
#
# The crate is a static library that resolves BoringSSL at runtime inside
# keystore2, so the build needs only BoringSSL's headers (openssl-sys bindgens the
# FFI from them) — no libcrypto.so of any ABI. Configure via environment:
#   NDK_HOME   Android NDK (default: newest under $ANDROID_HOME/ndk)
#   ABI        Android ABI (default: arm64-v8a)
#   API        platform level (default: 34)
#   BORINGSSL  BoringSSL source dir with include/ (cloned if unset/missing)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ABI="${ABI:-arm64-v8a}"
API="${API:-34}"

case "$ABI" in
  arm64-v8a)   TRIPLE=aarch64-linux-android ;;
  armeabi-v7a) TRIPLE=armv7-linux-androideabi ;;
  x86_64)      TRIPLE=x86_64-linux-android ;;
  x86)         TRIPLE=i686-linux-android ;;
  *) echo "unknown ABI: $ABI" >&2; exit 1 ;;
esac
ENVPREFIX="$(echo "$TRIPLE" | tr '[:lower:]-' '[:upper:]_')"

if [ -z "${NDK_HOME:-}" ]; then
  NDK_HOME="$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "$NDK_HOME" ] || { echo "NDK not found; set NDK_HOME" >&2; exit 1; }
# Set every NDK variable cargo-ndk consults to the one NDK we resolved, so it neither warns about a
# mismatch nor silently falls back to a different preinstalled NDK (CI runners preset ANDROID_NDK_ROOT).
export ANDROID_NDK_HOME="$NDK_HOME" ANDROID_NDK_ROOT="$NDK_HOME" ANDROID_NDK="$NDK_HOME"

# Adapt the reference TA to build under Cargo rather than Soong: the BoringSSL
# backend (openssl-sys vs bssl-sys, kmr-crypto-boring.patch) and a per-request
# attestation security level (kmr-ta-seclevel.patch). Each patch is applied to the
# submodule working tree, idempotently — skipped when it already reverse-applies,
# i.e. is already present.
for PATCH in "$HERE"/patches/*.patch; do
  if git -C "$ROOT/third_party/keymint" apply -p1 --reverse --check "$PATCH" 2>/dev/null; then
    :
  else
    git -C "$ROOT/third_party/keymint" apply -p1 "$PATCH"
  fi
done

BORINGSSL="${BORINGSSL:-$ROOT/third_party/boringssl}"
if [ ! -f "$BORINGSSL/include/openssl/base.h" ]; then
  git clone --depth 1 https://boringssl.googlesource.com/boringssl "$BORINGSSL"
fi

if [ -z "${LIBCLANG_PATH:-}" ]; then
  for p in /usr/lib /usr/lib64 /usr/lib/llvm/lib /usr/lib/x86_64-linux-gnu; do
    [ -e "$p/libclang.so" ] && export LIBCLANG_PATH="$p" && break
  done
fi

# Point openssl-sys straight at the BoringSSL headers so it neither vendors OpenSSL
# nor probes the host. The static library records a link directive for libcrypto
# but never links it; the interceptor's shared object leaves it to runtime.
export OPENSSL_NO_VENDOR=1
export "${ENVPREFIX}_OPENSSL_INCLUDE_DIR=$BORINGSSL/include"
export "${ENVPREFIX}_OPENSSL_LIB_DIR=$BORINGSSL"
export "${ENVPREFIX}_OPENSSL_STATIC=0"
export "${ENVPREFIX}_OPENSSL_LIBS=crypto"

cd "$HERE"
# cargo-ndk >= 4 sets bindgen's NDK-sysroot clang args (BINDGEN_EXTRA_CLANG_ARGS_*) by default; older
# 3.x needs an explicit --bindgen to do the same. openssl-sys bindgens the BoringSSL FFI, so it must
# see those args either way — detect which cargo-ndk is installed and pass the flag only when it exists.
BINDGEN=()
if cargo ndk --help 2>/dev/null | grep -q -- '--bindgen'; then BINDGEN=(--bindgen); fi

# `build.sh clippy` type-checks the crate with clippy instead of building the .a,
# enforcing its cast lints (capi's conversion functions deny them). It runs under
# the same NDK/BoringSSL env as a build, so it checks the exact target the
# interceptor ships for. Any other/absent argument builds the static library.
CARGO_CMD="${1:-build}"
cargo ndk -t "$ABI" --platform "$API" "${BINDGEN[@]}" "$CARGO_CMD" --release -p teesim-km

if [ "$CARGO_CMD" = build ]; then
  echo "Output: $HERE/target/$TRIPLE/release/libteesim_km.a"
fi
