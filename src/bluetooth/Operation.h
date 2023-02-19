#ifndef E5CFB89A_8548_4207_AE2F_2E5BE70F3909
#define E5CFB89A_8548_4207_AE2F_2E5BE70F3909

#include <iostream>
#include <string>
#include <vector>

#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "Item.h"
#include "Util.h"

#define PARAMETER_BYTEARRAY "data"

#define CORE_PARAMETER_BD_ADDR "bd_addr_t"
#define CORE_PARAMETER_HCI_HANDLE "hci_con_handle_t"
#define CORE_PARAMETER_HCI_HANDLE_SIZE 2
#define CORE_PARAMETER_CID "cid"
#define CORE_PARAMETER_CID_SIZE 2
#define CORE_PARAMETER_PSM "psm"
#define CORE_PARAMETER_PSM_SIZE 2

#define CORE_OPERATION_GAP_CONNECT "gap_connect" // bd_addr_t, bd_addr_type_t
#define CORE_OPERATION_GAP_CONNECT_CANCEL "gap_connect_cancel"
#define CORE_OPERATION_GAP_DISCONNECT "gap_disconnect"                 // hci_con_handle_t
#define CORE_OPERATION_L2CAP_CREATE_CHANNEL "l2cap_create_channel"     // bd_addr, psm
#define CORE_OPERATION_L2CAP_REGISTER_SERVICE "l2cap_register_service" // psm, gap_security_level

struct Parameter
{
    u32 id;

    std::string name;

    bool isEnum;

    u32 bytes;
    u32 min_bytes;
    u32 max_bytes;
    u8 *data;

    u32 offset;

    std::vector<std::vector<u8>> domain;
    std::vector<std::string> enum_domain;

    Parameter()
    {
    }
    Parameter(std::string _name, s32 _bytes) : name(_name), bytes(_bytes)
    {
    }

    bool generate();
};

class Operation : public Item
{
    s32 id;
    std::string name;
    bool isCore;
    u8 type;
    std::vector<Parameter> inputs;
    std::vector<std::string> exec;
    void dump();

    // u32 serialize(u8*);
    void deserialize(operation_t *);

    operation_t *pOp;

  public:
    Operation() = default;
    Operation(u32 _id, std::string _name) : id(_id), name(_name)
    {
    }
    Operation *arrange_bytes(u8 *buf);

    s32 ID()
    {
        return id;
    }
    std::string &Name()
    {
        return name;
    }

    std::vector<Parameter> &Inputs()
    {
        return inputs;
    }
    std::vector<std::string> &Exec()
    {
        return exec;
    }
    void set_type(bool _type)
    {
        type = _type;
    }
    u8 get_type()
    {
        return type;
    }
    bool core()
    {
        return name == CORE_OPERATION_GAP_CONNECT || name == CORE_OPERATION_GAP_CONNECT_CANCEL ||
               name == CORE_OPERATION_GAP_DISCONNECT || name == CORE_OPERATION_L2CAP_CREATE_CHANNEL ||
               name == CORE_OPERATION_L2CAP_REGISTER_SERVICE;
    }

    // bool generate() {
    //     bool res = true;
    //     for(Parameter* p : inputs)
    //        res = p->generate() && res;
    //     return res;
    // }
};

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

void deseralize(u8 *);

void init_parameters();
void init_operations();

#endif /* E5CFB89A_8548_4207_AE2F_2E5BE70F3909 */
