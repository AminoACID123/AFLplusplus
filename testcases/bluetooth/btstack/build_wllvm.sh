rm -rf wllvm_build
mkdir -p wllvm_build
cd wllvm_build
LLVM_COMPILER=clang cmake -DCMAKE_C_COMPILER=wllvm -DCMAKE_CXX_COMPILER=wllvm++ ../