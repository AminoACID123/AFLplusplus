set environment LD_LIBRARY_PATH=../../..
set args -i in -o out -j btstack_ops_new.json -k harness.c -q wllvm_build/libbtstack.a.bc -r ./afl_build/bt
