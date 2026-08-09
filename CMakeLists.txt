cmake_minimum_required(VERSION 3.22)
project(teesim LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# LSPlt provides memory-map scanning and PLT/GOT hooking.
set(LSPLT_JNI ${CMAKE_SOURCE_DIR}/third_party/lsplt/lsplt/src/main/jni)
add_library(lsplt STATIC ${LSPLT_JNI}/lsplt.cc ${LSPLT_JNI}/elf_util.cc)
target_include_directories(lsplt PUBLIC ${LSPLT_JNI}/include)
target_include_directories(lsplt PRIVATE ${LSPLT_JNI})

# The injector loads a shared library into a running process with ptrace and
# calls its entry point.
add_executable(inject injector/main.cpp injector/utils.cpp)
target_include_directories(inject PRIVATE injector/include)
target_link_libraries(inject PRIVATE lsplt log)
target_link_options(inject PRIVATE -static-libstdc++)
