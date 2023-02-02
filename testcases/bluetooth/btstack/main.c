#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__AFL_FUZZ_INIT();

__AFL_COVERAGE();

void stack_init();

void stack_execute(char *, int);

int main(int argc, const char *argv[]) {

  ///  __afl_coverage_off();

  stack_init();

  __AFL_INIT();

  //    __afl_coverage_on();

  // while(__AFL_LOOP(&to_continue)){

  //     int len = __AFL_FUZZ_TESTCASE_LEN;

  //     to_continue = buf[0];

  //     execute_one(buf + 1, len - 1);
  // }
  if (argc == 2) {
    static char buf[1024 * 1024];
    FILE *f = fopen("/home/xaz/Documents/AFLplusplus/testcases/bluetooth/"
                    "btstack/out/default/crashes/crash",
                    "rb");
    int len = fread(buf, 1, 1024 * 1024, f);
    stack_execute(buf, len);
  } else {
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    int len = __AFL_FUZZ_TESTCASE_LEN;
    stack_execute(buf, len);
  }

  return 0;
}
