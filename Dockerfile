FROM ubuntu:20.04

# ENV DEBIAN_FRONTEND=noninteractive
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y git build-essential wget g++ zlib1g-dev python3-pip \
        python-dev build-essential cmake autoconf libtool make \
        llvm-10 clang-10 libc++-dev libc++abi-dev \
        language-pack-en-base \
        && \
    apt-get clean


ENV PIN_TAR_NAME=pin-3.20-98437-gf02b61307-gcc-linux
ENV PIN_ROOT=/${PIN_TAR_NAME}

ENV MIRAGE_PATH=/fuzzer/build
ENV PATH=${PATH}:${MIRAGE_PATH}:${PIN_ROOT}

RUN wget http://software.intel.com/sites/landingpage/pintool/downloads/${PIN_TAR_NAME}.tar.gz -O /${PIN_TAR_NAME}.tar.gz \
    && tar xvf /${PIN_TAR_NAME}.tar.gz -C /

ADD . /fuzzer
RUN cd /fuzzer && ./build.sh

VOLUME ["/data"]

WORKDIR /data
# # ENTRYPOINT [ "/opt/env.init" ]
ENTRYPOINT [ "/bin/bash" ]