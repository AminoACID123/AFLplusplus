#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__AFL_FUZZ_INIT();

void harness_init();

void stack_init();

void stack_execute(char*, int);

int main(int argc, const char * argv[]){

    harness_init();

    stack_init();

    char* buf = __AFL_FUZZ_TESTCASE_BUF;

    int len = __AFL_FUZZ_TESTCASE_LEN; 

    stack_execute(buf, len);

    return 0;
}