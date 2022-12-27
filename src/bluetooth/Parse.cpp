#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <set>

#include "../../include/bluetooth.h"
#include "../../include/config.h"
#include "Operation.h"
#include "cJSON.h"

using namespace std;

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
    s32 i = 0;
    cJSON *item, *value, *_byte;
    cJSON *root = cJSON_GetObjectItem(file, "parameters");

    cJSON_ArrayForEach(item, root)
    {
        Parameter param;
        param.name = cJSON_GetObjectItem(item, "name")->valuestring;
        param.isEnum = cJSON_GetObjectItem(item, "enum")->valueint;
        cJSON *domain = cJSON_GetObjectItem(item, "domain");
        if (param.isEnum)
        {
            param.bytes = 1;
            cJSON_ArrayForEach(value, domain)
            {
                param.enum_domain.insert(value->valuestring);
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
                param.domain.insert(temp);
            }
            param.bytes = cJSON_GetObjectItem(item, "bytes")->valueint;
        }
        param.id = i++;
        parameters.push_back(param);
    }
}

void parse_operations(cJSON *file)
{
    cJSON *op;
    cJSON *root = cJSON_GetObjectItem(file, "operations");
    s32 i = 0;
    cJSON_ArrayForEach(op, root)
    {
        cJSON *input, *output, *str;
        cJSON *inputs = cJSON_GetObjectItem(op, "inputs");
        cJSON *outputs = cJSON_GetObjectItem(op, "outputs");
        cJSON *exec = cJSON_GetObjectItem(op, "exec");
        Operation operation;
        operation.name = cJSON_GetObjectItem(op, "name")->valuestring;
        cJSON_ArrayForEach(str, exec)
        {
            operation.exec.push_back(str->valuestring);
        }

        if(Operation* op = get_operation(operation.name))
        {
            op->exec.insert(op->exec.begin(), operation.exec.begin(), operation.exec.end());
            continue;
        }

        cJSON_ArrayForEach(input, inputs)
        {
            operation.inputs.push_back(get_parameter(input->valuestring));
        }

        cJSON_ArrayForEach(output, outputs)
        {
            operation.outputs.push_back(get_parameter(output->valuestring));
        }

        operations.push_back(operation);
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

    // fprintf(f, "#define NUM_PARAM %ld\n", parameters.size() + 1);
    // for (Operation *op : operations)
    // {
    //     if (op->inputs.size() > max_in)
    //         max_in = op->inputs.size();
    //     if (op->outputs.size() > max_out)
    //         max_out = op->outputs.size();
    // }
    // fprintf(f, "#define MAX_INPUT %d\n", max_in * 2);
    // fprintf(f, "#define MAX_OUTPUT %d\n", max_out);

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
               "extern u8* __afl_area3_ptr;\n");
    //            "u32   context_len[NUM_PARAM] = { ");
    // fprintf(f, "1");

    // for (u32 i = 1, n = parameter_list.size(); i != n; i++)
    // {
    //     fprintf(f, ", %d", parameter_list[i]->isEnum ? 1 : parameter_list[i]->bytes);
    // }
    // fprintf(f, "};\n\n");
}

/**
Write Static Functions and enum mappers
*/
void payload3(FILE *f)
{
    u32 i = 0;
    for (string &func : static_functions)
        fprintf(f, (func + "\n").c_str());

    for (Parameter& param : parameters)
    {
        if (param.isEnum)
        {
            u32 c = 0;
            fprintf(f, "%s e%d(u8 i) {\n", param.name.c_str(), param.id);
            fprintf(f, "switch(i) {\n");
            for (string e : param.enum_domain)
            {
                fprintf(f, "case %d: return %s;break;\n", c, e.c_str());
                c++;
            }
            fprintf(f, "default: return %s;\n", param.enum_domain.begin()->c_str());
            fprintf(f, "}\n}\n");
        }
    }
}

/**
Write Fuzz Targets
*/
void payload4(FILE *f)
{
    // fprintf(f, "void harness_init() {\n"
    //            "  for (int i = 0; i < NUM_PARAM; i++)\n"
    //            "    context[i] = malloc(sizeof(char) * context_len[i]);\n}\n");
    for (u32 i = 0, n = operations.size(); i != n; i++)
    {
        Operation op = operations[i];
        fprintf(f, "void operation%d() {\n", i);
        for (u32 j = 0; j < op.inputs.size(); j++)
        {
            Parameter *param = op.inputs[j];
            if (!param->isEnum)
            {
                fprintf(f, "  u8* _i%d = arg_in[%d];\n", j, j * 2);
                fprintf(f, "  u32 _s%d = *(u32*)arg_in[%d];\n", j, j * 2 + 1);
            }
            else
            {
                fprintf(f, "  %s _i%d = e%d(*(u8*)arg_in[%d]);\n", param->name.c_str(), j, param->id, j * 2);
            }
        }
        for (u32 j = 0; j < op.outputs.size(); j++)
        {
            fprintf(f, "  u8* _o%d = __afl_area3_ptr + %d;\n", j, op.outputs[j]->offset);
        }
        for (string &e : op.exec)
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
    for (int i = 0, n = operations.size(); i != n; i++)
    {
        fprintf(f, "  &operation%d", i);
        if (i != n - 1)
            fprintf(f, ",");
        fprintf(f, "\n");
    }
    fprintf(f, "};\n\n");
}

void generate_harness(const char *file)
{
    FILE *f = fopen(file, "w");
    payload1(f);
    payload2(f);
    payload3(f);
    fclose(f);
}

// extern "C" void generate_seeds(const char *dir)
// {
//     struct stat sb;
//     u8 buf[BT_MAX_BUFFER_SIZE];

//     if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode))
//     {
//         mkdir(dir, S_IRUSR | S_IWUSR);
//     }

//     for (u32 i = 0, n = operation_list.size(); i < n; i++)
//     {
//         char file[512];
//         sprintf(file, "%d", i);

//         FILE *F = fopen((string(dir) + "/" + file).c_str(), "w");

//         generate_random_operation(i, 0, buf);

//         fwrite(buf, 1, *(u32*)buf + sizeof(u32), F);
//         fclose(F);
//     }
// }


extern "C" void parse_operation(const char *in_file, const char *out_file)
{
    init_parameters();
    init_operations();

    cJSON *file = load_from_file(in_file);
    parse_headers(file);
    parse_static_functions(file);
    parse_parameters(file);
    parse_operations(file);
    // parse_harnesses(file);

    FILE *f = fopen(out_file, "w");
    payload1(f);
    payload2(f);
    payload3(f);
    payload4(f);
    fclose(f);
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