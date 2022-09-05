#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct Parameter {
  char *name;
  int   bytes;
  bool  discrete;
  void **domain;
  int domain_len;
} Parameter;

typedef struct Operation {
  char *        name;
  Parameter**    inputs;
  Parameter**    outputs;
  int           num_in;
  int           num_out;
} Operation;

typedef struct Harness {
  Operation *op;
  char **    inputs;
  char **    outputs;
  int        num_in;
  int        num_out;
}Harness;

Parameter* get_parameter(const char* name);

Operation* get_operation(const char* name);

void parse_operations(const char *file);

void parse_harnesses(const char* file);
