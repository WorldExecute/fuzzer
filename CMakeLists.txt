set(CMAKE_EXPORT_COMPILECOMMANDS ON)
cmake_minimum_required(VERSION 3.14)
project(mirage_fuzzer)


# support C++14 features used by LLVM 10.0.0
set(CMAKE_CXX_STANDARD 14)

if (NOT DEFINED ENV{LLVM_DIR})
    set(ENV{LLVM_DIR} /usr/include/llvm-10/llvm)
    message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
endif ()

#include_directories(/usr/lib/llvm-10/include/llvm)
find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
# 这里指向一个 symbolic link文件（linux下用ln创建的），该链接文件指向正确的目录所在。然而在Clion+WSL无法正确处理这种情形，导致没有正确的代码提示
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(./inc)

if ($ENV{CLION_IDE})
    include_directories(/usr/include/llvm-10/)
    #    include_directories(/usr/include/llvm-15/)
endif ()
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

# install(TARGETS mirage_fuzzer DESTINATION bin)

# install(TARGETS mirage_fuzzer
#         EXPORT MyLibTargets 
#         LIBRARY DESTINATION lib  # 动态库安装路径
#         ARCHIVE DESTINATION lib  # 静态库安装路径
#         RUNTIME DESTINATION bin  # 可执行文件安装路径
#         PUBLIC_HEADER DESTINATION include  # 头文件安装路径
#         )

