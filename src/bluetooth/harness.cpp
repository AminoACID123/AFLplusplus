#include "harness.h"
#include "bluetooth.h"
#include "cJSON.h"
#include <assert.h>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "../../include/bluetooth.h"
#include "../../include/config.h"

using namespace std;

// Parameter parameter_list[] = {
//     {
//         .name = "DATA"
//     },
//     {
//         .name = "BD_ADDR",
//         .bytes = 6,
//         .domain = {
//                     {(char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA},
//                     {(char)0xBB, (char)0xBB, (char)0xBB, (char)0xBB, (char)0xBB, (char)0xBB},
//                     {(char)0xCC, (char)0xCC, (char)0xCC, (char)0xCC, (char)0xCC, (char)0xCC}
//                 }
//     },
//     {
//         .name = "HCI_CONN_HANDLE",
//         .bytes = 2,
//         .domain = {
//                     {(char)0, (char)0},
//                     {(char)1, (char)0},
//                     {(char)2, (char)0}
//                 }
//     },
//     {
//         .name = "PHY_HANDLE",
//         .bytes = 2,
//         .domain = {
//                     {(char)0, (char)0},
//                     {(char)1, (char)0},
//                     {(char)2, (char)0}
//                 }
//     },
//     {
//         .name = "BD_ADDR_TYPE",
//         .bytes = 1,
//         .domain = {
//                     {(char)0}, {(char)1}, {(char)2}, {(char)3}, {(char)0xfc}, {(char)0xfd}
//                 }
//     },
//     {
//         .name = "CID",
//         .bytes = 2,
//         .domain = {
//                     {(char)1, (char)0},
//                     {(char)2, (char)0},
//                     {(char)4, (char)0},
//                     {(char)5, (char)0},
//                     {(char)6, (char)0},
//                     {(char)7, (char)0},
//                     {(char)8, (char)0},
//                     {(char)9, (char)0},
//                     {(char)10, (char)0}
//                 }
//     }
// };

vector<Parameter *> parameter_list;
vector<Operation *> operation_list;
// vector<Harness *> harness_list;

set<string> headers;
vector<string> static_functions;

void Operation::dump()
{
    printf("Operation: %s\n", name.c_str());
    for (Parameter *in : inputs)
        printf("    Parameter In: %s\n", in->name.c_str());
    for (Parameter *out : outputs)
        printf("    Parameter Out: %s\n", out->name.c_str());
}

// void Harness::dump()
// {
//     printf("Operation: %s\n", op->name.c_str());
//     for (string &header : headers)
//         printf("    Header: %s\n", header.c_str());
//     for (string &e : exec)
//         printf("    Exec: %s\n", e.c_str());
// }

cJSON *load_from_file(const char *file)
{
    u32 len;
    char *data;
    cJSON *root;
    FILE *f = fopen(file, "rb");
    /* get the length */
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    data = (char *)malloc(len + 1);

    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);

    root = cJSON_Parse(data);
    free(data);
    return root;
}

Parameter *get_parameter(string name)
{
    if (name.find("data") == 0)
    {
        Parameter *param = new Parameter;
        param->name = "data";
        param->isEnum = false;
        if (name.find('[') != name.npos)
        {
            sscanf(name.c_str(), "data[%d]", &param->bytes);
        }
        else
        {
            param->bytes = -1;
        }
        return param;
    }

    for (Parameter *param : parameter_list)
    {
        if (param && name == param->name)
            return param;
    }
    return NULL;
}

Operation *get_operation(string name)
{
    for (Operation *op : operation_list)
    {
        if (name == op->name)
            return op;
    }
    return NULL;
}

void parse_headers(cJSON *file)
{
    cJSON *item;
    cJSON *root = cJSON_GetObjectItem(file, "headers");
    cJSON_ArrayForEach(item, root)
    {
        headers.insert(item->valuestring);
    }
}

void parse_static_functions(cJSON *file)
{
    cJSON *item;
    cJSON *root = cJSON_GetObjectItem(file, "static_functions");
    cJSON_ArrayForEach(item, root)
    {
        static_functions.push_back(item->valuestring);
    }
}

void parse_parameters(cJSON *file)
{
    cJSON *item, *value, *_byte;
    cJSON *root = cJSON_GetObjectItem(file, "parameters");
    parameter_list.push_back(NULL);
    cJSON_ArrayForEach(item, root)
    {
        Parameter *param = new Parameter;
        cJSON *domain = cJSON_GetObjectItem(item, "domain");
        param->name = cJSON_GetObjectItem(item, "name")->valuestring;
        param->isEnum = cJSON_GetObjectItem(item, "enum")->valueint;
        if (param->isEnum)
        {
            cJSON_ArrayForEach(value, domain)
            {
                param->enum_domain.push_back(value->valuestring);
            }
        }
        else
        {
            cJSON_ArrayForEach(value, domain)
            {
                vector<u8> temp;
                cJSON_ArrayForEach(_byte, value)
                {
                    temp.push_back(_byte->valueint);
                }
                param->domain.push_back(temp);
            }
            param->bytes = cJSON_GetObjectItem(item, "bytes")->valueint;
        }
        parameter_list.push_back(param);
    }
}

void parse_operations(cJSON *file)
{
    cJSON *op;
    cJSON *root = cJSON_GetObjectItem(file, "operations");
    u32 i = 0;
    cJSON_ArrayForEach(op, root)
    {
        printf("%d\n", i++);
        cJSON *input, *output, *str;
        cJSON *inputs = cJSON_GetObjectItem(op, "inputs");
        cJSON *outputs = cJSON_GetObjectItem(op, "outputs");
        cJSON *exec = cJSON_GetObjectItem(op, "exec");
        Operation *operation = new Operation();
        operation->name = cJSON_GetObjectItem(op, "name")->valuestring;

        cJSON_ArrayForEach(input, inputs)
        {
            operation->inputs.push_back(get_parameter(input->valuestring));
        }

        cJSON_ArrayForEach(output, outputs)
        {
            operation->outputs.push_back(get_parameter(output->valuestring));
        }

        cJSON_ArrayForEach(str, exec)
        {
            operation->exec.push_back(str->valuestring);
        }
        operation_list.push_back(operation);
    }
}

// void parse_harnesses(cJSON *file)
// {
//     cJSON *hn;
//     cJSON *root = cJSON_GetObjectItem(file, "harnesses");
//     cJSON_ArrayForEach(hn, root)
//     {
//         cJSON *header, *exec;
//         cJSON *operation = cJSON_GetObjectItem(hn, "operation");
//         cJSON *execs = cJSON_GetObjectItem(hn, "exec");
//         Harness *harness = new Harness();
//         harness->op = get_operation(operation->valuestring);

//         cJSON_ArrayForEach(exec, execs)
//         {
//             harness->exec.push_back(exec->valuestring);
//         }
//         harness_list.push_back(harness);
//     }
// }

void parse(const char *fn)
{
    cJSON *file = load_from_file(fn);
    parse_parameters(file);
    parse_operations(file);
    // parse_harnesses(file);
}

void dump()
{
    for (Operation *op : operation_list)
        op->dump();
    // for (Harness *hn : harness_list)
    //     hn->dump();
}

/**
Write Headers and Macros
*/
void payload1(FILE *f)
{
    // fprintf(f, "#include \"%s\"", )
    u32 max_in = 0;
    u32 max_out = 0;

    for (const string &header : headers)
        fprintf(f, "#include \"%s\"\n", header.c_str());

    fprintf(f, "#define NUM_PARAM %ld\n", parameter_list.size() + 1);
    for (Operation *op : operation_list)
    {
        if (op->inputs.size() > max_in)
            max_in = op->inputs.size();
        if (op->outputs.size() > max_out)
            max_out = op->outputs.size();
    }
    fprintf(f, "#define MAX_INPUT %d\n", max_in * 2);
    fprintf(f, "#define MAX_OUTPUT %d\n", max_out);

    fprintf(f, "typedef uint8_t u8;\n");
    fprintf(f, "typedef uint16_t u16;\n");
    fprintf(f, "typedef uint32_t u32;\n");
}

/**
Write Global Variables
*/
void payload2(FILE *f)
{
    fprintf(f, "void *arg_in[MAX_INPUT];\n"
               "void *arg_out[MAX_OUTPUT];\n"
               "void *context[NUM_PARAM];\n"
               "u32   context_len[NUM_PARAM] = { ");
    fprintf(f, "1");

    for (u32 i = 1, n = parameter_list.size(); i != n; i++)
    {
        fprintf(f, ", %d", parameter_list[i]->isEnum ? 1 : parameter_list[i]->bytes);
    }
    fprintf(f, "};\n\n");
}

/** 
Write Static Functions and enum mappers
*/
void payload3(FILE *f)
{
    u32 i = 0;
    for (string &func : static_functions)
        fprintf(f, (func + "\n").c_str());

    for (Parameter *param : parameter_list)
    {
        if (param && param->isEnum){
        u32 c = 0;
        fprintf(f, "%s e%d(u8 i) {\n", param->name.c_str(), i);
        fprintf(f, "switch(i) {\n");
        for (string &e : param->enum_domain)
        {
            fprintf(f, "case %d: return %s;break;\n", c, e.c_str());
            c++;
        }
        fprintf(f, "}\n}\n");
        }
        i++;
    }
}

/**
Write Fuzz Targets
*/
void payload4(FILE *f)
{        
    fprintf(f, "void harness_init() {\n"
               "  for (int i = 0; i < NUM_PARAM; i++)\n"
               "    context[i] = malloc(sizeof(char) * context_len[i]);\n}\n");
    for (u32 i = 0, n = operation_list.size(); i != n; i++)
    {

        Operation *op = operation_list[i];
        fprintf(f, "void operation%d() {\n", i);
        for (u32 j = 0; j < op->inputs.size(); j++)
        {
            Parameter* param = op->inputs[j];
            if(!param->isEnum){
            fprintf(f, "  u8* _i%d = arg_in[%d];\n", j, j * 2);
            fprintf(f, "  u32 _s%d = *(u32*)arg_in[%d];\n", j, j * 2 + 1);
            }
            else{
                u32 idx = get_parameter_idx(param);
                fprintf(f, "  %s _i%d = e%d(*(u8*)arg_in[%d]);\n", param->name.c_str(), j, idx, j*2);
            }
        }
        for (u32 j = 0; j < op->outputs.size(); j++)
        {
            int idx = get_parameter_idx(op->outputs[j]);
            fprintf(f, "  u8* _o%d = context[%d];\n", j, idx);
        }
        for (string &e : op->exec)
        {
            for (int k = 0; k < e.length(); k++)
            {
                if (e[k] == '$')
                    e[k] = '_';
            }
            fprintf(f, "  %s\n", e.c_str());
        }
        fprintf(f, "}\n\n");
    }

    fprintf(f, "typedef void (*fun_ptr)();\n"
               "fun_ptr FUZZ_LIST[] = {\n");
    for (int i = 0, n = operation_list.size(); i != n; i++)
    {
        fprintf(f, "  &operation%d", i);
        if (i != n - 1)
            fprintf(f, ",");
        fprintf(f, "\n");
    }
    fprintf(f, "};\n\n");
}

u32 get_operation_idx(Operation *op)
{
    for (u32 i = 0, n = operation_list.size(); i < n; i++)
    {
        if (operation_list[i] == op)
            return i;
    }
    return -1;
}

u32 get_parameter_idx(Parameter *param)
{
    if(param->name == "data")
        return 0;
    for (u32 i = 1, n = parameter_list.size(); i < n; i++)
    {
        if (parameter_list[i] == param)
            return i;
    }
    assert(false && "Unknown parameter");
    return 0;
}

void generate_harness(const char *file)
{
    FILE *f = fopen(file, "w");
    payload1(f);
    payload2(f);
    payload3(f);
    fclose(f);
}

extern "C" void generate_seeds(const char *dir)
{
    struct stat sb;
    u8 buf[BT_MAX_BUFFER_SIZE];

    if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode))
    {
        mkdir(dir, S_IRUSR | S_IWUSR);
    }

    for (u32 i = 0, n = operation_list.size(); i < n; i++)
    {
        char file[512];
        sprintf(file, "%d", i);

        FILE *F = fopen((string(dir) + "/" + file).c_str(), "w");

        generate_random_operation(i, 0, buf);

        fwrite(buf, 1, *(u32*)buf + sizeof(u32), F);
        fclose(F);
    }
}

extern "C" void generate_random_operation(u32 idx, u32 seed, u8 *out_buf)
{
    Operation *op = operation_list[idx];
    u32 arg_in_cnt = op->inputs.size();

    struct operation_header
    {
        u32 size;
        u8 flag;
        u32 operation_idx;
        u32 arg_in_cnt;
    } __attribute__((packed));

    struct parameter_header
    {
        u32 arg_idx;
        u32 arg_len;
    } __attribute__((packed));

    operation_header *hdr = (operation_header *)out_buf;
    hdr->flag = OPERATION;
    hdr->operation_idx = idx;
    hdr->arg_in_cnt = arg_in_cnt;

    u32 i = sizeof(operation_header);
    for (Parameter *param : op->inputs)
    {
        parameter_header *param_hdr = (parameter_header *)(out_buf + i);
        if (param->name == "data")
        {
            u32 len = (param->bytes == -1 ? 1 + seed % (BT_MAX_PARAM_SIZE-1) : param->bytes);
            u8* param_buf = new u8[len];
            param_hdr->arg_len = len;
            memcpy(out_buf + i + sizeof(parameter_header), param_buf, len);
            i += (sizeof(parameter_header) + len);
            delete[] param_buf;
        }
        else
        {
            param_hdr->arg_idx = get_parameter_idx(param);
            if (param->isEnum){
                param_hdr->arg_len = 1;
                out_buf[i + sizeof(parameter_header)] = seed % param->enum_domain.size();
            }
            else{
                u32 j = seed % param->domain.size();
                param_hdr->arg_len = param->bytes;
                memcpy(out_buf + i + sizeof(parameter_header), param->domain[j].data(), param->domain[j].size());
            }
            i += (sizeof(parameter_header) + param->bytes);
        }
    }
    hdr->size = i - 4;
}

extern "C" u32 get_total_operation()
{
    return operation_list.size();
}

extern "C" void parse_operation(const char *in_file, const char *out_file)
{
    cJSON *file = load_from_file(in_file);
    parse_headers(file);
    parse_static_functions(file);
    parse_parameters(file);
    parse_operations(file);
    // parse_harnesses(file);

    printf("%d\n\n", operation_list.size());

    FILE *f = fopen(out_file, "w");
    payload1(f);
    payload2(f);
    payload3(f);
    payload4(f);
    fclose(f);

}

extern "C" bool parameter_has_domain(u32 op_idx, u32 param_idx)
{
    return operation_list[op_idx]->inputs[param_idx]->name != "data";
}

extern "C" void set_parameter(u32 op_idx, u32 param_idx, u8* buf, u32 seed)
{
    Parameter* param = operation_list[op_idx]->inputs[param_idx];
    assert(param->name != "data" && "Setting a parameter with no domain");
    if(param->isEnum)
        *buf = seed % param->enum_domain.size();
    else {
        u32 i = seed % param->domain.size();
        memcpy(buf, param->domain[i].data(), param->bytes);
    }
}

/*
int main(int argc, char **argv)
{
    if (argc != 4)
    {
        printf("Usage: afl-gen <input_operations> <output_harness> "
               "<output_seeds_dir>\n");
        exit(-1);
    }

    parse(argv[1]);
    dump();
    generate_harness(argv[2]);
    generate_seeds(argv[3]);

    return 0;
}
*/