rm -rf afl_build
mkdir -p afl_build
cd afl_build
cmake -DCMAKE_C_COMPILER=afl-clang-lto -DCMAKE_CXX_COMPILER=afl-clang-lto++ ../