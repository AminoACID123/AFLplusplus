set environment LD_LIBRARY_PATH=../../..
set args -i in -o out -j nimble_ops.json -k harness.c -q wllvm_build/bt.bc -r -H nimble  ./afl_build/bt
