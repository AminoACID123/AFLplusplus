rm -rf afl_build
mkdir -p afl_build
cd afl_build
echo "CC := afl-clang-lto" > Makefile
echo "CXX := afl-clang-lto++" >> Makefile
echo "LD := afl-clang-lto" >> Makefile
cat ../Makefile >> Makefile