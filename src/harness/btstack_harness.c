
#include <stdlib.h>

#define NUM_PARAM 1
#define MAX_INPUT 1
#define MAX_OUTPUT 1

static char **arg_in;
static char **arg_out;
static char * context[1];
static int    context_len[2];

void fuzz_init() {
  for (int i = 0; i < NUM_PARAM; i++)
    context[i] = malloc(sizeof(char) * context_len[i]);
}

void harness1(char **arg_in, char **arg_out) {
  char *_i0 = arg_in[0];
  char *_i1 = arg_in[1];
  gap_connect(_i0, _i1);
}

typedef void (*fun_ptr)(char **, char **);

fun_ptr FUZZ_LIST[] = {
  &harness1
};

/*
filed                   bytes
----------------------------------
harness_id              4
arg_in_count            4
arg1_idx                4
arg1_len                4
arg1_data               --
arg_out_count           4
arg1_idx                4

*/

void execute(char *test, int len) {
  int pos = 0;

  while (pos < len) {
    int id = *(int *)(test + pos);
    pos += sizeof(int);
    fun_ptr fun = FUZZ_LIST[id];
    int     args = *(int *)(test + pos);
    pos += sizeof(int);
    for (int i = 0; i < args; i++) {
      int idx = *(int *)(test + pos);
      pos += sizeof(int);
      if (idx == -1) {
        int len = *(int *)(test + pos);
        pos += sizeof(int);
        arg_in[i] = test + pos;
        pos += len;
      } else {
        arg_in[i] = context[idx];
      }
    }

    args = *(int *)(test + pos);
    pos += sizeof(int);
    for (int i = 0; i < args; i++) {
      int idx = *(int *)(test + pos);
      pos += sizeof(int);
      arg_out[i] = context[idx];
    }
    fun(arg_in, arg_out);
  }
}
