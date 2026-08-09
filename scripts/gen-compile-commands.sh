#!/usr/bin/env bash
# Generate a compile database for clangd covering all of the project's C++ —
# the injector, the keymint interceptor, and the legacy keystore interceptor.
#
# Only a CMake configure runs (compile_commands.json is written at configure time);
# nothing is compiled. A placeholder CRYPTO_STATIC_LIB is enough to configure the
# keystore targets so their sources are indexed too. .clangd points here.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK:-}}
if [ -z "$NDK" ]; then
  NDK=$(ls -d "${ANDROID_HOME:?set ANDROID_HOME or ANDROID_NDK_HOME}"/ndk/* 2>/dev/null | sort -V | tail -1)
fi
[ -d "$NDK" ] || { echo "NDK not found: $NDK" >&2; exit 1; }

cmake -B build/compdb -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 \
  -DCRYPTO_STATIC_LIB=for-indexing-only >/dev/null

echo "compile database ready: build/compdb/compile_commands.json (used by .clangd)"
