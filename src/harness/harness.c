#include "cJSON.h"
#include "harness.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Operation *operations;
int        num_op;

Harness *harnesses;
int      num_hn;

Parameter parameters[] = {
    {.name = "DATA"},
    {.name = "BD_ADDR",
     .bytes = 6,
     .domain = {{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
                {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
                {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}}},
    {.name = "HCI_CONN_HANDLE", .bytes = 2, .domain = {{0, 0}, {1, 0}, {2, 0}}},
    {.name = "BD_ADDR_TYPE",
     .bytes = 1,
     .domain = {{0}, {1}, {2}, {3}, {0xfc}, {0xfd}}}};

cJSON *load_from_file(const char *file) {
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

Parameter *getParam(const char *name) {
  int n = sizeof(parameters) / sizeof(Parameter);

  for (int i = 0; i < n; i++) {
    if (strcmp(name, parameters[i].name) == 0) { return &parameters[i]; }
  }

  return NULL;
}

void load_operations(const char *file) {

  cJSON *root = cJSON_GetObjectItem(load_from_file(file), "operations");

  int n = cJSON_GetArraySize(root);
  operations = malloc(sizeof(Operation) * n);
  memset(operations, 0, sizeof(Operation) * n);

  for(int i=0;i<n;i++){
    int t;
    cJSON* item = cJSON_GetArrayItem(root, i);
    cJSON *inputs = cJSON_GetObjectItem(item, "inputs");
    cJSON *outputs = cJSON_GetObjectItem(item, "outputs");
    operations[i].name = cJSON_GetObjectItem(item, "name")->valuestring;

    t = cJSON_GetArraySize(inputs);
    operations[i].num_in = t;
    t = cJSON_GetArraySize(outputs);
    operations[i].outputs = malloc(t * sizeof(Parameter *));

    cJSON_ArrayForEach(in, inputs){
        char* param = in->valuestring;
        operations[i].inputs[n++] = getParam(param);
    }

    n = cJSON_GetArrayItem()

    i++;
  }
}

void load_harnesses(const char *file) {
  cJSON *root = cJSON_GetObjectItem(load_from_file(file), "operations");
}

void generate_harness(const char *file) {
}

int main() {
  cJSON *root = load_from_file("btstack_ops.json");
  char * out = cJSON_Print(root);
  printf("%s", out);
  return 0;
}