#ifndef E5CFB89A_8548_4207_AE2F_2E5BE70F3909
#define E5CFB89A_8548_4207_AE2F_2E5BE70F3909

#include <string>
#include <vector>

#include "../../include/bluetooth.h"
#include "../../include/types.h"

struct Parameter
{
    u32 id;

    std::string name;

    bool isEnum;

    u32 bytes;
    u32 min_bytes;
    u32 max_bytes;
    u8 data[BT_MAX_PARAM_SIZE];

    u32 offset;

    std::vector<std::vector<u8>> domain;
    std::vector<std::string> enum_domain;

    Parameter(){}
    Parameter(std::string _name, s32 _bytes):name(_name), bytes(_bytes){}

    bool operator < (Parameter& other) const {
        return name < other.name;
    }
};

struct Operation
{
    s32 id;
    std::string name;
    bool isCore;
    std::vector<Parameter *> inputs;
    std::vector<Parameter *> outputs;
    std::vector<std::string> exec;
    void dump();

    u32 size();

    void serialize(u8*);

    Parameter* param(u32 i){
        assert(i < inputs.size());
        return inputs[i];
    }

    Operation() {}
    Operation(std::string _name, bool _isCore): name(_name), isCore(_isCore){}
};


#define CORE_PARAMETER_HCI_HANDLE               "hci_con_handle_t"
#define CORE_PARAMETER_HCI_HANDLE_SIZE          2
#define CORE_PARAMETER_CID                      "cid"
#define CORE_PARAMETER_CID_SIZE                 2
#define CORE_PARAMETER_PSM                      "psm"
#define CORE_PARAMETER_PSM_SIZE                 2

#define CORE_OPERATION_GAP_CONNECT                    "gap_connect"           // bd_addr_t, bd_addr_type_t
#define CORE_OPERATION_GAP_CONNECT_CANCEL             "gap_connect_cancel"
#define CORE_OPERATION_GAP_DISCONNECT                 "gap_disconnect"       // hci_con_handle_t
#define CORE_OPERATION_L2CAP_CREATE_CHANNEL           "l2cap_create_channel"     // bd_addr, psm
#define CORE_OPERATION_L2CAP_REGISTER_SERVICE         "l2cap_register_service"     //psm, gap_security_level


// struct item_header{
//     u32 size;
//     u8 data[0];
// }__attribute__((packed));

// struct operation_header{
//     u8 flag;
//     u32 operation_idx;
//     u32 arg_in_cnt;
//     u8 data[0];
// } __attribute__((packed));

// struct parameter_header{
//     u32 len;
//     u8  data[0];
// } __attribute__((packed));

extern std::vector<Parameter> parameters;
extern std::vector<Operation> operations;

Parameter *get_parameter(std::string name);
Operation *get_operation(std::string name);
Operation *get_operation(u32 id);

void init_parameters();
void init_operations();

void define_operation(char* name, ...);
void define_parameter(char* name, ...);

#endif /* E5CFB89A_8548_4207_AE2F_2E5BE70F3909 */
