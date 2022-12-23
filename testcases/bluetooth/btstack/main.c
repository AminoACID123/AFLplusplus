#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__AFL_FUZZ_INIT();

__AFL_COVERAGE();

void harness_init();

void stack_init();

void stack_execute(char*, int);

int main(int argc, const char * argv[]){

  ///  __afl_coverage_off();

    harness_init();

    stack_init();

    __AFL_INIT();

    //    __afl_coverage_on();

    // while(__AFL_LOOP(&to_continue)){
        
    //     int len = __AFL_FUZZ_TESTCASE_LEN; 
        
    //     to_continue = buf[0];

    //     execute_one(buf + 1, len - 1);
    // }

char* buf = __AFL_FUZZ_TESTCASE_BUF;
   int len = __AFL_FUZZ_TESTCASE_LEN;

//char buf[2048];

// FILE* f =fopen("/home/xaz/Documents/AFLplusplus/testcases/bluetooth/btstack/crashes/id:000000,sig:06,src:000346,time:112531,execs:957846,op:havoc,rep:16","rb");
//int len = fread(buf, 1, 2048, f);

    stack_execute(buf, len);

    return 0;
}
