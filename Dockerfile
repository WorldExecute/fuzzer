FROM ubuntu:20.04

# Install dependencies
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y \
        cargo \
        sudo \
        cmake \
        g++ \
        git \
        libz3-dev \
        python2 \
        zlib1g-dev \
        vim \
        build-essential \
        binutils-gold \
        binutils-dev \
        curl \
        wget \
        python-dev \
        python3 \
        python3-dev \
        python3-pip \
        automake \
        python-bs4 \
        libboost-all-dev \
        python3-distutils \
        llvm-12-tools \
        autoconf libtool make language-pack-en-base \
        ninja-build flex bison zlib1g-dev cargo 
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install update 
RUN python3 -m pip install --upgrade pip \
    &&  python3 -m pip install networkx pydot pydotplus lit



RUN wget http://software.intel.com/sites/landingpage/pintool/downloads/${PIN_TAR_NAME}.tar.gz -O /${PIN_TAR_NAME}.tar.gz \
    && tar xvf /${PIN_TAR_NAME}.tar.gz -C /

# Download the LLVM sources already so that we don't need to get them again when SymCC changes
RUN git clone -b llvmorg-12.0.1 --depth 1 https://github.com/llvm/llvm-project.git /llvm-project 

# Build LLVM and some components
RUN mkdir -p /build/build-llvm/llvm  \
  && cd /build/build-llvm/llvm \
  &&  cmake -G "Ninja" /llvm-project/llvm \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;libcxx;libcxxabi;compiler-rt" \
    -DLLVM_TARGETS_TO_BUILD="X86"  \
    -DLLVM_BINUTILS_INCDIR=/usr/include \
  && ninja && ninja install 


# Install the Gold plugin
RUN mkdir -p /usr/lib/bfd-plugins \
    && cp /usr/local/lib/libLTO.so /usr/lib/bfd-plugins \
    && cp /usr/local/lib/LLVMgold.so /usr/lib/bfd-plugins

ENV PIN_TAR_NAME=pin-3.20-98437-gf02b61307-gcc-linux
ENV PIN_ROOT=/${PIN_TAR_NAME}
ENV MIRAGE_PATH=/fuzzer/build
ENV PATH=${PATH}:${MIRAGE_PATH}:${PIN_ROOT}
ENV PATH /build/build-llvm/llvm/bin:$PATH
ENV LLVM_SRC /llvm-project
ENV LLVM_OBJ /build/build-llvm/llvm
ENV LLVM_DIR /build/build-llvm/llvm


ADD . /fuzzer
RUN cd /fuzzer && ./build.sh

VOLUME ["/data"]

WORKDIR /data
# # ENTRYPOINT [ "/opt/env.init" ]
ENTRYPOINT [ "/bin/bash" ]