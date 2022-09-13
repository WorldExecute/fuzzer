git clone https://github.com/Matthias-Wandel/jhead.git

cd jhead

mirage-clang init

make clean
USE_PIN=1 CC=mirage-clang make 
cp ./jhead ../jhead-pin

make clean
USE_PHANTOM=1 CC=mirage-clang make 
cp ./jhead ../jhead-phan

make clean
USE_SOURCE=1 CC=mirage-clang make 
cp ./jhead ../jhead-src

make clean
USE_ASAN=1 USE_AFL=1 CC=mirage-clang make 
cp ./jhead ../jhead-asan

