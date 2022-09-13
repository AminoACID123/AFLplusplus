#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__AFL_FUZZ_INIT();

void stack_init();

void stack_execute(char*, int);

int main(int argc, const char * argv[]){

    stack_init();

    __AFL_INIT();

    buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000)) {

        len = __AFL_FUZZ_TESTCASE_LEN; 

        stack_execute(buf, len);

    }

    return 0;
}