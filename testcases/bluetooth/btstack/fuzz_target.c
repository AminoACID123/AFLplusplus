
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
__AFL_FUZZ_INIT();

int main() {

  // anything else here, e.g. command line arguments, initialization, etc.


  __AFL_INIT();


  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP! 

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

    if (len < 8) continue;  // check for a required/useful minimum input length
int k[3];
    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    //if(len == 8 && buf[4] == 'a')
     //   abort();
    if(len == 512 && buf[128] == 's')
        abort();
    /* Reset state. e.g. libtarget_free(tmp) */

  }

  return 0;

}
