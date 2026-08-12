cmake_minimum_required(VERSION 3.22)
project(teesim LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Weak-link NDK symbols newer than the minimum SDK so the code builds against a
# low min-SDK; the symbols we use are present on the devices we target.
add_compile_definitions(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)

# External inputs. libbinder_ndk and liblog come from the NDK sysroot; BoringSSL is
# resolved at runtime inside keystore2, so only its headers (for the Rust bindings)
# are needed at build time. The build depends on no device, so any ABI cross-builds.
set(BORINGSSL_DIR "${CMAKE_SOURCE_DIR}/third_party/boringssl" CACHE PATH "BoringSSL source directory containing include/")
# Native API floor for the Rust static lib (cargo ndk --platform). Track the same min-SDK
# AGP compiles the C++ at (ANDROID_PLATFORM, e.g. android-29) so both halves share one floor.
if(ANDROID_PLATFORM MATCHES "android-([0-9]+)")
  set(ANDROID_API_LEVEL "${CMAKE_MATCH_1}")
else()
  set(ANDROID_API_LEVEL "29")
endif()

# --- LSPlt: memory-map scanning and PLT/GOT hooking -------------------------
set(LSPLT_JNI ${CMAKE_SOURCE_DIR}/third_party/lsplt/lsplt/src/main/jni)
add_library(lsplt STATIC ${LSPLT_JNI}/lsplt.cc ${LSPLT_JNI}/elf_util.cc)
target_include_directories(lsplt PUBLIC ${LSPLT_JNI}/include)
target_include_directories(lsplt PRIVATE ${LSPLT_JNI})

# --- The injector -----------------------------------------------------------
add_executable(inject injector/main.cpp injector/utils.cpp)
target_include_directories(inject PRIVATE injector/include)
target_link_libraries(inject PRIVATE lsplt log)
target_link_options(inject PRIVATE -static-libstdc++)

# --- KeyMint AIDL, generated with the NDK backend ---------------------------
find_program(AIDL_BIN aidl)
if(NOT AIDL_BIN AND DEFINED ENV{ANDROID_HOME})
  file(GLOB _bt $ENV{ANDROID_HOME}/build-tools/*)
  find_program(AIDL_BIN aidl PATHS ${_bt} NO_DEFAULT_PATH)
endif()
if(NOT AIDL_BIN)
  message(FATAL_ERROR "aidl not found; set -DAIDL_BIN=/path/to/aidl")
endif()

set(SEC ${CMAKE_SOURCE_DIR}/third_party/interfaces/security)
set(KM_AIDL ${SEC}/keymint/aidl)
set(SC_AIDL ${SEC}/secureclock/aidl)
set(SS_AIDL ${SEC}/sharedsecret/aidl)
set(AIDL_GEN ${CMAKE_BINARY_DIR}/aidl-gen)

if(NOT EXISTS ${AIDL_GEN}/.done)
  file(MAKE_DIRECTORY ${AIDL_GEN}/src ${AIDL_GEN}/include)
  foreach(pkg keymint secureclock sharedsecret)
    file(GLOB _aidls ${SEC}/${pkg}/aidl/android/hardware/security/${pkg}/*.aidl)
    execute_process(
      COMMAND ${AIDL_BIN} --lang=ndk --structured --stability=vintf --min_sdk_version=29
              -I ${KM_AIDL} -I ${SC_AIDL} -I ${SS_AIDL}
              -o ${AIDL_GEN}/src -h ${AIDL_GEN}/include ${_aidls}
      RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
      message(FATAL_ERROR "aidl generation failed for ${pkg}")
    endif()
  endforeach()
  # The NDK AIDL's fromBinder already handles a LOCAL binder whose AIBinder_Class differs from our
  # statically-linked copy (a legacy km_compat IKeyMintDevice / IKeyMintOperation): when
  # AIBinder_associateClass fails it falls back to a descriptor match and builds a Bp, but only under
  # #if __ANDROID_API__ >= 31. keymint_aidl is compiled at API 31 below to enable that branch; require
  # the generated code to actually contain it so an aidl too old to emit the fallback fails the build
  # here rather than silently returning null on legacy devices.
  if(NOT EXISTS ${AIDL_GEN}/src/android/hardware/security/keymint/IKeyMintDevice.cpp)
    message(FATAL_ERROR "keymint: aidl did not generate IKeyMintDevice.cpp")
  endif()
  file(READ ${AIDL_GEN}/src/android/hardware/security/keymint/IKeyMintDevice.cpp _dev_cpp)
  if(NOT _dev_cpp MATCHES "AIBinder_Class_getDescriptor")
    message(FATAL_ERROR "keymint: generated fromBinder lacks the local-binder fallback; "
                        "build with build-tools >= 35 (36 recommended)")
  endif()
  file(TOUCH ${AIDL_GEN}/.done)
endif()

set(FN ${CMAKE_SOURCE_DIR}/third_party/frameworks-native/libs/binder/ndk)
file(GLOB_RECURSE AIDL_SRCS ${AIDL_GEN}/src/*.cpp)
add_library(keymint_aidl STATIC ${AIDL_SRCS})
target_include_directories(keymint_aidl PUBLIC
    ${AIDL_GEN}/include ${FN}/include_cpp ${FN}/include_ndk ${FN}/include_platform)
# keymint_aidl links only into teesim_keymint.so, which is injected into keystore2 (API 31+ only), so
# compile it at API 31 to enable the AIDL's own local-binder fallback in fromBinder (gated
# #if __ANDROID_API__ >= 31). The AIBinder_Class_getDescriptor it then calls is left undefined here and
# resolved at runtime against keystore2's libbinder_ndk (teesim_keymint links with -Wl,-z,undefs). The
# rest of the module keeps its lower min-SDK floor; only this static lib is raised. The NDK toolchain's
# compiler target ends in the API level, so bump that suffix to 31.
if(CMAKE_CXX_COMPILER_TARGET MATCHES "[0-9]+$")
  string(REGEX REPLACE "[0-9]+$" "31" _km_target "${CMAKE_CXX_COMPILER_TARGET}")
  target_compile_options(keymint_aidl PRIVATE "--target=${_km_target}")
else()
  message(FATAL_ERROR "keymint: cannot derive an API-31 target from '${CMAKE_CXX_COMPILER_TARGET}'")
endif()

# --- The in-process TA (Rust static library) --------------------------------
if(ANDROID_ABI STREQUAL "arm64-v8a")
  set(RUST_TRIPLE aarch64-linux-android)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
  set(RUST_TRIPLE armv7-linux-androideabi)
elseif(ANDROID_ABI STREQUAL "x86_64")
  set(RUST_TRIPLE x86_64-linux-android)
elseif(ANDROID_ABI STREQUAL "x86")
  set(RUST_TRIPLE i686-linux-android)
endif()

set(RUST_A ${CMAKE_SOURCE_DIR}/rust/target/${RUST_TRIPLE}/release/libteesim_km.a)
# ALWAYS invoke build.sh and let cargo decide incrementally what to rebuild. An OUTPUT custom command
# with no source DEPENDS only runs when the .a is missing, so once built it was never refreshed on a
# Rust source change — that once linked a stale 14-argument teesim_km_init_ex against a 16-argument C++
# caller (ids read from the wrong stack slot → SIGSEGV, keystore2 crash loop). cargo leaves the .a's
# mtime untouched when nothing changed, so this does not needlessly relink the interceptor.
add_custom_target(rust_ta
    BYPRODUCTS ${RUST_A}
    COMMAND ${CMAKE_COMMAND} -E env
            ABI=${ANDROID_ABI} API=${ANDROID_API_LEVEL} NDK_HOME=${ANDROID_NDK}
            BORINGSSL=${BORINGSSL_DIR}
            bash ${CMAKE_SOURCE_DIR}/rust/build.sh
    VERBATIM USES_TERMINAL)

# --- How the TAs reach BoringSSL --------------------------------------------
# The two interceptors resolve BoringSSL differently, and a single configure now
# builds both:
#   * keymint (keystore2, Android 12+) links a stub libcrypto.so — empty functions
#     carrying the right SONAME — and lets the host process's real libcrypto provide
#     the symbols at runtime. exports.map hides everything but `entry`, so the stub
#     never leaks.
#   * keystore (Android 10/11) bundles a modern static BoringSSL, because the host's
#     libcrypto is too old. That static `crypto` target is built internally below via
#     add_subdirectory, inheriting this build's Android toolchain.
# CRYPTO_STATIC_LIB stays as an optional override for a pre-built libcrypto.a.
set(CRYPTO_STUB_C ${CMAKE_BINARY_DIR}/libcrypto_stub.c)
file(STRINGS ${CMAKE_SOURCE_DIR}/keymint/libcrypto.syms _crypto_syms)
set(_stub_body "")
foreach(_s ${_crypto_syms})
  string(APPEND _stub_body "void ${_s}(void){}\n")
endforeach()
file(WRITE ${CRYPTO_STUB_C} "${_stub_body}")
add_library(crypto_stub SHARED ${CRYPTO_STUB_C})
set_target_properties(crypto_stub PROPERTIES OUTPUT_NAME crypto)
target_link_options(crypto_stub PRIVATE -nostdlib -Wl,-soname,libcrypto.so)
set(CRYPTO_LINK crypto_stub)

# The static BoringSSL the keystore interceptor bundles. Only the `crypto` target is
# referenced, so BoringSSL's tools and tests never build (Go stays optional). A
# caller may instead point CRYPTO_STATIC_LIB at a pre-built libcrypto.a.
set(CRYPTO_STATIC_LIB "" CACHE FILEPATH "Pre-built static libcrypto.a to bundle; empty = build BoringSSL internally")
if(CRYPTO_STATIC_LIB)
  set(KEYSTORE_CRYPTO ${CRYPTO_STATIC_LIB})
else()
  set(BUILD_SHARED_LIBS OFF)
  add_subdirectory(${BORINGSSL_DIR} ${CMAKE_BINARY_DIR}/boringssl EXCLUDE_FROM_ALL)
  set(KEYSTORE_CRYPTO crypto)
endif()

# --- The injected interceptor library ---------------------------------------
add_library(teesim_keymint SHARED
    keymint/keymint_router.cpp keymint/keymint_hook.cpp keymint/keymint_entry.cpp
    common/control.cpp common/json.cpp)
add_dependencies(teesim_keymint rust_ta)
target_include_directories(teesim_keymint PRIVATE
    keymint common injector/include rust/teesim-km/include ${LSPLT_JNI}/include)
# libbinder_ndk and liblog come from the NDK sysroot; libcrypto is either the
# runtime stub (shadowed by the host's copy) or a bundled static BoringSSL.
target_link_libraries(teesim_keymint PRIVATE keymint_aidl lsplt ${RUST_A} ${CRYPTO_LINK} binder_ndk log)
target_link_options(teesim_keymint PRIVATE
    -static-libstdc++
    # Binder/log calls newer than the min-SDK are absent from the NDK stub; let them
    # stay undefined here and resolve at runtime against keystore2's own libraries.
    -Wl,-z,undefs
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/keymint/exports.map
    -Wl,--gc-sections)

# --- Legacy keystore interceptor (Android 10/11) ----------------------------
# Apps reach the keystore daemon over the C++ libbinder, which is not in the NDK.
# Link stub libbinder/libutils (empty definitions carrying the right C++ ABI and
# SONAMEs) so the device's real libraries provide the implementations at runtime.
# The TA's crypto is bundled here (KEYSTORE_CRYPTO, a static BoringSSL) rather than
# resolved from the host's older libcrypto.
# The platform libbinder exports BBinder's vtable but not its RTTI typeinfo, so
# anything deriving from BBinder must be built without RTTI (and, to match, without
# exceptions) or it fails to load.
set(AOSP ${CMAKE_SOURCE_DIR}/keystore/aosp)
set(BINDER_CXX_FLAGS -fno-rtti -fno-exceptions)
add_library(utils_stub SHARED ${AOSP}/stub_utils.cpp)
set_target_properties(utils_stub PROPERTIES OUTPUT_NAME utils)
target_include_directories(utils_stub PRIVATE ${AOSP}/include)
target_compile_definitions(utils_stub PRIVATE BINDER_DISABLE_NATIVE_HANDLE)
target_compile_options(utils_stub PRIVATE ${BINDER_CXX_FLAGS})

add_library(binder_stub SHARED ${AOSP}/stub_binder.cpp)
set_target_properties(binder_stub PROPERTIES OUTPUT_NAME binder)
target_include_directories(binder_stub PRIVATE ${AOSP}/include)
target_compile_definitions(binder_stub PRIVATE BINDER_DISABLE_NATIVE_HANDLE)
target_compile_options(binder_stub PRIVATE ${BINDER_CXX_FLAGS})
target_link_libraries(binder_stub PRIVATE utils_stub)

add_library(teesim_keystore SHARED
    keystore/binder_interceptor.cpp keystore/keystore_router.cpp keystore/keystore_entry.cpp
    common/control.cpp common/json.cpp)
add_dependencies(teesim_keystore rust_ta)
target_include_directories(teesim_keystore PRIVATE
    keystore common ${AOSP}/include injector/include ${LSPLT_JNI}/include
    rust/teesim-km/include ${BORINGSSL_DIR}/include)
target_compile_definitions(teesim_keystore PRIVATE BINDER_DISABLE_NATIVE_HANDLE)
target_compile_options(teesim_keystore PRIVATE ${BINDER_CXX_FLAGS})
target_link_libraries(teesim_keystore PRIVATE
    binder_stub utils_stub lsplt log ${RUST_A} ${KEYSTORE_CRYPTO})
target_link_options(teesim_keystore PRIVATE
    -static-libstdc++
    -Wl,-z,undefs
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/keymint/exports.map
    -Wl,--gc-sections)
