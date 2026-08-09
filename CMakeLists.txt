cmake_minimum_required(VERSION 3.22)
project(teesim LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Weak-link NDK symbols newer than the minimum SDK so the code builds against a
# low min-SDK; the symbols we use are present on the devices we target.
add_compile_definitions(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)

# External inputs. The library links the platform BoringSSL and libbinder_ndk,
# resolved at runtime inside keystore2; at build time it links copies for the
# target ABI (pulled from a device) and BoringSSL headers for the Rust bindings.
set(DEVICE_LIB_DIR "" CACHE PATH "Directory holding the target ABI's libbinder_ndk.so and libcrypto.so")
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
            BORINGSSL=${BORINGSSL_DIR} LIBDIR=${DEVICE_LIB_DIR}
            bash ${CMAKE_SOURCE_DIR}/rust/build.sh
    VERBATIM USES_TERMINAL)
add_custom_target(rust_ta DEPENDS ${RUST_A})

# --- The injected interceptor library ---------------------------------------
add_library(teesim_keymint SHARED
    keymint/keymint_router.cpp keymint/keymint_hook.cpp keymint/keymint_entry.cpp)
add_dependencies(teesim_keymint rust_ta)
target_include_directories(teesim_keymint PRIVATE
    keymint injector/include rust/teesim-km/include ${LSPLT_JNI}/include)
target_link_directories(teesim_keymint PRIVATE ${DEVICE_LIB_DIR})
target_link_libraries(teesim_keymint PRIVATE keymint_aidl lsplt ${RUST_A} binder_ndk crypto log)
target_link_options(teesim_keymint PRIVATE
    -static-libstdc++
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/keymint/exports.map
    -Wl,--gc-sections)
