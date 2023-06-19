set(CMAKE_EXPORT_COMPILECOMMANDS ON)
cmake_minimum_required(VERSION 3.14)
project(mirage_fuzzer
    VERSION 0.0.1
    DESCRIPTION "Mirage Fuzzer : An Experimental Fuzzer to Use Phantom Fuzzing to Enhance Fuzzing Performance"
    LANGUAGES CXX C    
)

# Check whether the OS is Linux
if (NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    message(FATAL_ERROR "The OS is not Linux")
endif ()

# Set the compiler to clang/clang++ if not specified
if (NOT DEFINED CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER clang)
endif ()

if (NOT DEFINED CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER clang++)
endif ()

# Check clang version == 10
execute_process(COMMAND ${CMAKE_C_COMPILER} --version OUTPUT_VARIABLE clang_version)
string(REGEX MATCH "clang version 10" clang_version ${clang_version})
message(STATUS "clang version: ${clang_version}")
if (NOT clang_version)
    message(FATAL_ERROR "The clang version is not 10")
endif ()



# Check whether the compiler is clang/clang++
if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "The compiler is not clang")
endif ()
if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "The compiler is not clang++")
endif ()


# support C++14 features used by LLVM 10.0.0
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use libc++ for clang, instead of libstdc++
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

#include_directories(/usr/lib/llvm-10/include/llvm)
find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(./inc)

# if ($ENV{CLION_IDE})
#     include_directories(/usr/include/llvm-10/)
# endif ()
message(STATUS "include_directories of: ${LLVM_INCLUDE_DIRS}")

link_directories(${LLVM_LIBRARY_DIRS})

set(MIRAGE_BIN_DIR ".")
set(MIRAGE_LIB_DIR "runtime")
set(MIRAGE_PASS_DIR "pass")


add_subdirectory(pass)
add_subdirectory(runtime)
add_subdirectory(compiler)
add_subdirectory(fuzzer)
add_subdirectory(pin_track)


