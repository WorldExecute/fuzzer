set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set the compiler to clang/clang++ if not specified
# set(CMAKE_C_COMPILER clang)
# set(CMAKE_CXX_COMPILER clang++)

if (NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER clang)
endif ()
if (NOT CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER clang++)
endif ()

cmake_minimum_required(VERSION 3.14)
project(mirage_fuzzer
    VERSION 0.0.1
    DESCRIPTION "Mirage Fuzzer : An Experimental Fuzzer to Use Mirage Fuzzing to Enhance Fuzzing Performance"
    LANGUAGES CXX C    
)

# Check whether the OS is Linux
if (NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    message(FATAL_ERROR "The OS is not Linux")
endif ()



# Check clang version == 10
# execute_process(COMMAND ${CMAKE_C_COMPILER} --version OUTPUT_VARIABLE clang_version)
# string(REGEX MATCH "clang version 10" clang_version ${clang_version})
# message(STATUS "clang version: ${clang_version}")
# if (NOT clang_version)
#     message(FATAL_ERROR "The clang version is not 10")
# endif ()



# Check whether the compiler is clang/clang++
# if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
#     message(FATAL_ERROR "The compiler is not clang")
# endif ()
# if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
#     message(FATAL_ERROR "The compiler is not clang++")
# endif ()


# support C++14 features used by LLVM 10.0.0
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(./inc)
# Use libc++ for clang, instead of libstdc++
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

#include_directories(/usr/lib/llvm-10/include/llvm)
find_package(LLVM REQUIRED CONFIG)

# print LLVM Version
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
# Append LLVM's cmake directory to CMAKE_MODULE_PATH
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
# Now set LLVM's cmake directory, so that add_llvm_* works
include(AddLLVM)

add_definitions(${LLVM_DEFINITIONS})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})


link_directories(${LLVM_LIBRARY_DIRS})

set(MIRAGE_BIN_DIR ".")
set(MIRAGE_LIB_DIR "runtime")
set(MIRAGE_PASS_DIR "pass")


add_subdirectory(pass)
add_subdirectory(runtime)
add_subdirectory(compiler)
add_subdirectory(fuzzer)
add_subdirectory(pin_track)
add_subdirectory(driver)


