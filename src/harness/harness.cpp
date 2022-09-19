#include "cJSON.h"
#include "harness.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <sys/uio.h>
#include <sys/stat.h>

#include "../../include/config.h"

using namespace std;

Parameter param_list[] = {
    {.name = "DATA"},
    {.name = "BD_ADDR",
     .bytes = 6,
     .domain = {{(char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA,
                 (char)0xAA},
                {(char)0xBB, (char)0xBB, (char)0xBB, (char)0xBB, (char)0xBB,
                 (char)0xBB},
                {(char)0xCC, (char)0xCC, (char)0xCC, (char)0xCC, (char)0xCC,
                 (char)0xCC}}},
    {.name = "HCI_CONN_HANDLE",
     .bytes = 2,
     .domain = {{(char)0, (char)0}, {(char)1, (char)0}, {(char)2, (char)0}}},
    {.name = "BD_ADDR_TYPE",
     .bytes = 1,
     .domain = {{(char)0},
                {(char)1},
                {(char)2},
                {(char)3},
                {(char)0xfc},
                {(char)0xfd}}}};

void Operation::dump() {
  printf("Operation: %s\n", name.c_str());
  for (Parameter *in : inputs)
    printf("    Parameter In: %s\n", in->name.c_str());
  for (Parameter *out : outputs)
    printf("    Parameter Out: %s\n", out->name.c_str());
}

void Harness::dump() {
  printf("Operation: %s\n", op->name.c_str());
  for (string &header : headers)
    printf("    Header: %s\n", header.c_str());
  for (string &e : exec)
    printf("    Exec: %s\n", e.c_str());
}

HarnessManager::HarnessManager() {
  int n = sizeof(param_list) / sizeof(Parameter);
  for (int i = 0; i < n; i++)
    parameters.push_back(param_list[i]);
}

cJSON *HarnessManager::load_from_file(const char *file) {
  int    len;
  char * data;
  cJSON *root;
  FILE * f = fopen(file, "rb");
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

Parameter *HarnessManager::get_parameter(string name) {
  for (Parameter &param : parameters)
    if (name == param.name) { return &param; }
  return NULL;
}

Operation *HarnessManager::get_operation(string name) {
  for (Operation *op : operations)
    if (name == op->name) { return op; }
  return NULL;
}

void HarnessManager::parse_operations(const char *file) {
  cJSON *op;
  cJSON *root = cJSON_GetObjectItem(load_from_file(file), "operations");
  cJSON_ArrayForEach(op, root) {
    cJSON *    input, *output;
    cJSON *    inputs = cJSON_GetObjectItem(op, "inputs");
    cJSON *    outputs = cJSON_GetObjectItem(op, "outputs");
    Operation *operation = new Operation();
    operation->name = cJSON_GetObjectItem(op, "name")->valuestring;

    cJSON_ArrayForEach(input, inputs) {
      operation->inputs.push_back(get_parameter(input->valuestring));
    }

    cJSON_ArrayForEach(output, outputs) {
      operation->outputs.push_back(get_parameter(output->valuestring));
    }
    operations.push_back(operation);
  }
}

void HarnessManager::parse_harnesses(const char *file) {
  cJSON *hn;
  cJSON *root = cJSON_GetObjectItem(load_from_file(file), "harnesses");
  cJSON_ArrayForEach(hn, root) {
    cJSON *  header, *exec;
    cJSON *  operation = cJSON_GetObjectItem(hn, "operation");
    cJSON *  headers = cJSON_GetObjectItem(hn, "headers");
    cJSON *  execs = cJSON_GetObjectItem(hn, "exec");
    Harness *harness = new Harness();
    harness->op = get_operation(operation->valuestring);

    cJSON_ArrayForEach(header, headers) {
      harness->headers.push_back(header->valuestring);
    }

    cJSON_ArrayForEach(exec, execs) {
      harness->exec.push_back(exec->valuestring);
    }
    harnesses.push_back(harness);
  }
}

void HarnessManager::parse(const char *file) {
  parse_operations(file);
  parse_harnesses(file);
}

void HarnessManager::dump() {
  for (Operation *op : operations)
    op->dump();
  for (Harness *hn : harnesses)
    hn->dump();
}

/**
Write Headers and Macros
*/
void HarnessManager::payload1(FILE *f) {
  // fprintf(f, "#include \"%s\"", )
  int         max_in = 0;
  int         max_out = 0;
  set<string> headers;

  for (Harness *hn : harnesses) {
    for (string &header : hn->headers)
      headers.insert(header);
  }
  for (const string &header : headers)
    fprintf(f, "#include \"%s\"\n", header.c_str());

  fprintf(f, "#define NUM_PARAM %d\n", parameters.size() - 1);
  for (Operation *op : operations) {
    if (op->inputs.size() > max_in) max_in = op->inputs.size();
    if (op->outputs.size() > max_out) max_out = op->outputs.size();
  }
  fprintf(f, "#define MAX_INPUT %d\n", max_in);
  fprintf(f, "#define MAX_OUTPUT %d\n", max_out);
}

/**
Write Global Variables
*/
void HarnessManager::payload2(FILE *f) {
  fprintf(f,
          "char *arg_in[MAX_INPUT];\n"
          "char *arg_out[MAX_OUTPUT];\n"
          "char *context[NUM_PARAM];\n"
          "int   context_len[NUM_PARAM] = { ");

  for (int i = 1, n = parameters.size(); i != n; i++) {
    fprintf(f, "%d", parameters[i].bytes);
    if (i != n - 1) fprintf(f, ",");
  }
  fprintf(f, "};\n\n");
}

/**
Write Fuzz Targets
*/
void HarnessManager::payload3(FILE *f) {
  fprintf(f,
          "void harness_init() {\n"
          "  for (int i = 0; i < NUM_PARAM; i++)\n"
          "    context[i] = malloc(sizeof(char) * context_len[i]);\n}\n");
  for (int i = 0, n = harnesses.size(); i != n; i++) {
    Harness *hn = harnesses[i];
    fprintf(f, "void harness%d(char **arg_in, char **arg_out) {\n", i);
    for (int j = 0; j < hn->op->inputs.size(); j++) {
      fprintf(f, "  char* _i%d = arg_in[%d];\n", j, j);
    }
    for (int j = 0; j < hn->op->outputs.size(); j++) {
      fprintf(f, "  char* _o%d = arg_out[%d];\n", j, j);
    }
    for (string &e : hn->exec) {
      for (int k = 0; k < e.length(); k++) {
        if (e[k] == '$') e[k] = '_';
      }
      fprintf(f, "  %s\n", e.c_str());
    }
    fprintf(f, "}\n\n");
  }

  fprintf(f,
          "typedef void (*fun_ptr)(char **, char **);\n"
          "fun_ptr FUZZ_LIST[] = {\n");
  for (int i = 0, n = harnesses.size(); i != n; i++) {
    fprintf(f, "  &harness%d", i);
    if (i != n - 1) fprintf(f, ",");
    fprintf(f, "\n");
  }
  fprintf(f, "};\n\n");
}

void HarnessManager::generate_harness(const char *file) {
  FILE *f = fopen(file, "w");
  payload1(f);
  payload2(f);
  payload3(f);
  fclose(f);
}

void HarnessManager::generate_seeds(const char *dir) {
  struct stat sb;

  if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
    mkdir(dir, S_IRUSR | S_IWUSR);
  }

  for (int i = 0, n = harnesses.size(); i < n; i++) {
    Harness *hn = harnesses[i];
    char     file[512];
    int len = 0;
    char flag = F_API;
    int harness_idx = i;
    int arg_in_cnt = hn->op->inputs.size();
    int arg_out_cnt = hn->op->outputs.size();

    sprintf(file, "%d", i);

    FILE *F = fopen((string(dir) + "/" + file).c_str(), "w");

    fwrite(&len, 4, 1, F);
    fwrite(&flag, 1, 1, F);
    fwrite(&harness_idx, 4, 1, F);

    fwrite(&arg_in_cnt, 4, 1, F);
    for (int j = 0, n = hn->op->inputs.size(); j < n; j++) {
      Parameter *input = hn->op->inputs[j];
      int idx = get_parameter_idx(input);
      fwrite(&idx, 4, 1, F);
      if(input->name != "DATA"){
        int size = input->bytes;
        fwrite(&size, 4, 1, F);
        fwrite(input->domain[0].data(), 1, size, F);
      } else {
        int size = 16;
        unsigned data[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
        fwrite(&size, 4, 1, F);
        fwrite(data, 4, 4, F);
      }
    }

    fwrite(&arg_out_cnt, 4, 1, F);
    for (int j = 0, n = hn->op->outputs.size(); j < n; j++) {
      Parameter *output = hn->op->outputs[j];
      int idx = get_parameter_idx(output);
      fwrite(&idx, 4, 1, F);
    }

    long pos = ftell(F);
    len = pos - 4;
    fseek(F,0,SEEK_SET);
    fwrite(&len, 4, 1, F);
    fclose(F);
  }

}

int main(int argc, char **argv) {
  if (argc != 4) {
    printf(
        "Usage: afl-gen <input_operations> <output_harness> "
        "<output_seeds_dir>\n");
    exit(-1);
  }

  HarnessManager hmgr;
  hmgr.parse(argv[1]);
  hmgr.dump();
  hmgr.generate_harness(argv[2]);
  hmgr.generate_seeds(argv[3]);

  return 0;
}