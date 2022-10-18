#include "cJSON.h"
#include <string>
#include <vector>

struct Parameter
{
    std::string name;
    int bytes;
    std::vector<std::vector<char>> domain;
};

struct Operation
{
    std::string name;
    std::vector<Parameter *> inputs;
    std::vector<Parameter *> outputs;
    void dump();
};

struct Harness
{
    Operation *op;
    std::vector<std::string> headers;
    std::vector<std::string> exec;
    void dump();
};

extern Parameter param_list[];
extern std::vector<Operation*> operation_list;
extern std::vector<Harness*> harness_list;

cJSON *load_from_file(const char *file);
void parse_parameters();
void parse_operations(const char *file);
void parse_harnesses(const char *file);
void payload1(FILE *f);
void payload2(FILE *f);
void payload3(FILE *f);

int get_operation_idx(Operation *op);
int get_parameter_idx(Parameter *param);

Parameter *get_parameter(std::string name);
Operation *get_operation(std::string name);
void parse(const char *file);
void generate_harness(const char *file);
void generate_seeds(const char *dir);
void dump();


void dump_operation(Operation *op);