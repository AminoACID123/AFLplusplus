#include <vector>
#include <string>

struct Parameter {
  std::string                    name;
  int                            bytes;
  std::vector<std::vector<char>> domain;
};

struct Operation {
  std::string            name;
  std::vector<Parameter*> inputs;
  std::vector<Parameter*> outputs;
  void dump();
};

struct Harness {
  Operation *              op;
  std::vector<std::string> headers;
  std::vector<std::string> exec;
  void dump();
};

class HarnessManager {
  std::vector<Parameter> parameters;
  std::vector<Operation*> operations;
  std::vector<Harness*>   harnesses;
  cJSON *load_from_file(const char *file);
  void parse_operations(const char *file);
  void parse_harnesses(const char *file);
  void payload1(FILE *f);
  void payload2(FILE *f);
  void payload3(FILE *f);

 public:
  HarnessManager();
  Parameter *get_parameter(std::string name);
  Operation *get_operation(std::string name);
  void parse(const char* file);
  void generate(const char* file);
  void dump();
};

void dump_operation(Operation *op);