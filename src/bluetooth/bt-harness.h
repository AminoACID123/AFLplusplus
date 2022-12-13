#include "cJSON.h"
#include <string>
#include <vector>

#include "../../include/types.h"

struct Parameter
{
    std::string name;
    bool isEnum;
    s32 bytes;
    std::vector<std::vector<u8>> domain;
    std::vector<std::string> enum_domain;
};

struct Operation
{
    std::string name;
    std::vector<Parameter *> inputs;
    std::vector<Parameter *> outputs;
    std::vector<std::string> exec;
    void dump();
};

#define CORE_OPERATION_NUM 4
#define CORE_PARAMETER_NUM 5

extern std::vector<Parameter*> parameter_list;
extern std::vector<Operation*> operation_list;
extern std::string core_parameters[CORE_PARAMETER_NUM];
extern std::string core_operations[CORE_OPERATION_NUM];

static inline bool is_core_parameter(std::string name)
{
    for(std::string& param : core_parameters)
        if(param == name)
            return true;
    return false;
}

static inline bool is_core_operation(std::string name)
{
    for(std::string& op : core_operations)
        if(op == name)
            return true;
    return false;
}

static inline u32 get_core_parameter_num()
{
    return sizeof(core_parameters) / sizeof(std::string);
}

static inline u32 get_core_operation_num()
{
    return sizeof(core_operations) / sizeof(std::string);
}

cJSON *load_from_file(const char *file);
void parse_parameters();
void parse_operations(const char *file);
void payload1(FILE *f);
void payload2(FILE *f);
void payload3(FILE *f);

u32 get_operation_idx(Operation *op);
u32 get_parameter_idx(Parameter *param);

Parameter *get_parameter(std::string name);
Operation *get_operation(std::string name);
void parse(const char *file);
void dump();


void dump_operation(Operation *op);