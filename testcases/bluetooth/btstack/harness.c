#include "gap.h"
#define NUM_PARAM 3
#define MAX_INPUT 2
#define MAX_OUTPUT 1
char *arg_in[MAX_INPUT];
char *arg_out[MAX_OUTPUT];
char *context[NUM_PARAM];
int   context_len[NUM_PARAM] = { 6,2,1};

void harness_init() {
  for (int i = 0; i < NUM_PARAM; i++)
    context[i] = malloc(sizeof(char) * context_len[i]);
}
void harness0(char **arg_in, char **arg_out) {
  char* _o0 = arg_out[0];
  gap_local_bd_addr(_o0);
}

void harness1(char **arg_in, char **arg_out) {
  char* _i0 = arg_in[0];
  char* _i1 = arg_in[1];
  gap_connect(_i0, _i1);
}

void harness2(char **arg_in, char **arg_out) {
  char* _i0 = arg_in[0];
  gap_disconnect(_i0);
}

void harness3(char **arg_in, char **arg_out) {
  char* _i0 = arg_in[0];
  gap_advertisements_set_data(sizeof(_i0),_i0);
}

typedef void (*fun_ptr)(char **, char **);
fun_ptr FUZZ_LIST[] = {
  &harness0,
  &harness1,
  &harness2,
  &harness3
};

