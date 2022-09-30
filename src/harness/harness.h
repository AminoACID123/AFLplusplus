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
  Operation *                         op;
  std::vector<std::vector<char>>      iValues;
  std::vector<std::string>            headers;
  std::vector<std::string>            exec;
  void dump();
};

class HarnessManager {
private:
  static HarnessManager* manager;

  HarnessManager(){}

  std::vector<Parameter> parameters;
  std::vector<Operation*> operations;
  std::vector<Harness*>   harnesses;
  cJSON *load_from_file(const char *file);
  void parse_parameters();
  void parse_operations(const char *file);
  void parse_harnesses(const char *file);
  void payload1(FILE *f);
  void payload2(FILE *f);
  void payload3(FILE *f);

  inline int get_operation_idx(Operation* op) {
    for(int i=0,n=operations.size();i<n;i++){
      if(operations[i] == op) return i;
    }
    return -1;
  }

  inline int get_parameter_idx(Parameter* param) {
    for(int i=0,n=parameters.size();i<n;i++) {
      if(&parameters[i] == param) return i;
    }
    return -1;
  }

 public:
  static HarnessManager* get(){
    if(manager == nullptr)
      return new HarnessManager();
    return manager;
  }
  Parameter *get_parameter(std::string name);
  Operation *get_operation(std::string name);
  void parse(const char* file);
  void generate_harness(const char* file);
  void generate_seeds(const char* dir);
  void dump();
};

void dump_operation(Operation *op);