#include "cJSON.h"
#include <string>
#include <vector>

#include "../../include/types.h"


static inline cJSON *load_from_file(const char *file)
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


void parse_parameters();
void parse_operations(const char *file);
void payload1(FILE *f);
void payload2(FILE *f);
void payload3(FILE *f);

void parse(const char *file);
