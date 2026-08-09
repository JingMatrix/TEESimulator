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
set(ANDROID_API_LEVEL "34" CACHE STRING "Android platform level for the Rust build")

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
  file(TOUCH ${AIDL_GEN}/.done)
endif()

set(FN ${CMAKE_SOURCE_DIR}/third_party/frameworks-native/libs/binder/ndk)
file(GLOB_RECURSE AIDL_SRCS ${AIDL_GEN}/src/*.cpp)
add_library(keymint_aidl STATIC ${AIDL_SRCS})
target_include_directories(keymint_aidl PUBLIC
    ${AIDL_GEN}/include ${FN}/include_cpp ${FN}/include_ndk ${FN}/include_platform)

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
add_custom_command(
    OUTPUT ${RUST_A}
    COMMAND ${CMAKE_COMMAND} -E env
            ABI=${ANDROID_ABI} API=${ANDROID_API_LEVEL} NDK_HOME=${ANDROID_NDK}
            BORINGSSL=${BORINGSSL_DIR}
            bash ${CMAKE_SOURCE_DIR}/rust/build.sh
    VERBATIM USES_TERMINAL)
add_custom_target(rust_ta DEPENDS ${RUST_A})

# --- How the TA reaches BoringSSL -------------------------------------------
# On keystore2 (Android 12+) BoringSSL lives in the host process, so we link only
# a stub libcrypto.so (empty functions with the right SONAME) and let the host's
# real libcrypto provide the symbols at runtime. On Android 10 the host's libcrypto
# is too old, so CRYPTO_STATIC_LIB bundles a modern static BoringSSL instead.
set(CRYPTO_STATIC_LIB "" CACHE FILEPATH "Static libcrypto.a to bundle; empty = resolve libcrypto at runtime via a stub")
if(CRYPTO_STATIC_LIB)
  set(CRYPTO_LINK ${CRYPTO_STATIC_LIB})
else()
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
endif()

# --- The injected interceptor library ---------------------------------------
add_library(teesim_keymint SHARED
    keymint/keymint_router.cpp keymint/keymint_hook.cpp keymint/keymint_entry.cpp)
add_dependencies(teesim_keymint rust_ta)
target_include_directories(teesim_keymint PRIVATE
    keymint injector/include rust/teesim-km/include ${LSPLT_JNI}/include)
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
# Built only when a static BoringSSL is supplied: on Android 10/11 the TA's crypto
# is bundled (CRYPTO_STATIC_LIB) rather than resolved from the host's older libcrypto.
# The platform libbinder exports BBinder's vtable but not its RTTI typeinfo, so
# anything deriving from BBinder must be built without RTTI (and, to match, without
# exceptions) or it fails to load.
if(CRYPTO_STATIC_LIB)
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
    keystore/binder_interceptor.cpp keystore/keystore_router.cpp keystore/keystore_entry.cpp)
add_dependencies(teesim_keystore rust_ta)
target_include_directories(teesim_keystore PRIVATE
    keystore ${AOSP}/include injector/include ${LSPLT_JNI}/include
    rust/teesim-km/include ${BORINGSSL_DIR}/include)
target_compile_definitions(teesim_keystore PRIVATE BINDER_DISABLE_NATIVE_HANDLE)
target_compile_options(teesim_keystore PRIVATE ${BINDER_CXX_FLAGS})
target_link_libraries(teesim_keystore PRIVATE
    binder_stub utils_stub lsplt log ${RUST_A} ${CRYPTO_STATIC_LIB})
target_link_options(teesim_keystore PRIVATE
    -static-libstdc++
    -Wl,-z,undefs
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/keymint/exports.map
    -Wl,--gc-sections)
endif()
