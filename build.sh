#!/bin/bash
SHELL_PATH=$(readlink -f "$0")
ROOT_DIR=$(dirname ${SHELL_PATH})

BIN_DIR=${ROOT_DIR}/build
CMAKE_BUILD_DIR=${ROOT_DIR}/build-cmake

set -euxo pipefail

# export CC=clang
# export CXX=clang++

PREFIX=${PREFIX:-${BIN_DIR}}

rm -rf ${PREFIX}
mkdir -p ${PREFIX}
cd ${ROOT_DIR}/lib
# Cound not set CC/CXX before building libdft64, as it would build failed.
# Some CFLAGS/CXXFLAGS are not compatible with clang/gcc.
unset CC CXX CFLAGS CXXFLAGS
./build-lib.sh
cd ${ROOT_DIR}

export CC=/usr/bin/clang-10
export CXX=/usr/bin/clang++-10

cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
    -DWRAPPED_CLANG=$CC \
    -DWRAPPED_CLANGXX=$CXX \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} -S ${ROOT_DIR} -B ${CMAKE_BUILD_DIR}
make -C ${CMAKE_BUILD_DIR} # VERBOSE=1
make -C ${CMAKE_BUILD_DIR} install # VERBOSE=1