rm -rf wllvm_build
mkdir -p wllvm_build
cd wllvm_build
echo "export LLVM_COMPILER := clang" > Makefile
echo "CC := wllvm" > Makefile
echo "CXX := wllvm++" >> Makefile
echo "LD := wllvm" >> Makefile
echo "include ../Makefile" >> Makefile
# cat ../Makefile >> Makefile
