#include "cJSON.h"
#include <string>
#include <vector>

#include "../../include/types.h"
#include "Operation.h"


cJSON *load_from_file(const char *file);
void parse_parameters();
void parse_operations(const char *file);
void payload1(FILE *f);
void payload2(FILE *f);
void payload3(FILE *f);

s32 get_operation_idx(Operation *op);
s32 get_parameter_idx(Parameter *param);


void parse(const char *file);
void dump();


void dump_operation(Operation *op);