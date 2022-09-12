BIN_DIR=$(readlink -f "$0")
CUR_DIR=$(dirname ${BIN_DIR})
cd ${CUR_DIR}
make -C ${CUR_DIR}/libdft64
echo "build libdft64"
export CFLAGS='-g -O2 -Wall -fPIE'
export CXXFLAGS='-g -O2 -Wall -fPIE'
export CPPFLAGS='-g -O2 -Wall -fPIE'
if ! [ -f "/usr/local/lib/libudis86.a" ]; then
    cd ${CUR_DIR}/udis86
    ./autogen.sh && ./configure && make -j && make install
    echo "build libudis86"
fi