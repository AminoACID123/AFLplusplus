#include "cJSON.h"
#include <string>
#include <vector>

#include "../../include/types.h"

struct Parameter
{
    s32 idx;
    std::string name;
    bool isEnum;
    s32 bytes;
    std::vector<std::vector<u8>> domain;
    std::vector<std::string> enum_domain;
};

struct Operation
{
    s32 idx;
    std::string name;
    std::vector<Parameter *> inputs;
    std::vector<Parameter *> outputs;
    std::vector<std::string> exec;
    void dump();
};

struct operation_header{
    u32 size;
    u8 flag;
    u32 operation_idx;
    u32 arg_in_cnt;
} __attribute__((packed));

struct parameter_header{
    u32 arg_idx;
    u32 arg_len;
    u8  data[0];
} __attribute__((packed));

#define CORE_OPERATION_NUM 4
#define CORE_PARAMETER_NUM 5

#define CORE_OPERATION_GAP_CONNECT              "gap_connect"           // bd_addr_t, bd_addr_type_t
#define CORE_OPERATION_GAP_CONNECT_SIZE         (sizeof(operation_header) + 2 * sizeof(parameter_header) + CORE_PARAMETER_BD_ADDR_SIZE + CORE_PARAMETER_BD_ADDR_TYPE_SIZE - sizeof(u32))
#define CORE_OPERATION_GAP_DISCONNECT           "gap_disconnect"       // hci_con_handle_t
#define CORE_OPERATION_GAP_DISCONENCT_SIZE      (sizeof(operation_header) + sizeof(parameter_header) + CORE_PARAMETER_HCI_HANDLE_SIZE - sizeof(u32))
#define CORE_OPERATION_L2CAP_CREATE_CHANNEL     "l2cap_create_channel"     // bd_addr
#define CORE_OPERATION_L2CAP_CREATE_CHANNEL_SIZE (sizeof(operation_header) + sizeof(parameter_header) + CORE_PARAMETER_BD_ADDR_SIZE - sizeof(u32))
#define CORE_OPERATION_L2CAP_REGISTER_SERVICE   "l2cap_register_service"     //psm
#define CORE_OPERATION_L2CAP_REGISTER_SERVICE_SIZE  (sizeof(operation_header) + sizeof(parameter_header) + CORE_PARAMETER_PSM_SIZE - sizeof(u32))

#define CORE_PARAMETER_BD_ADDR                  "bd_addr_t"
#define CORE_PARAMETER_BD_ADDR_SIZE             6
#define CORE_PARAMETER_HCI_HANDLE               "hci_con_handle_t"
#define CORE_PARAMETER_HCI_HANDLE_SIZE          2
#define CORE_PARAMETER_BD_ADDR_TYPE             "bd_addr_type_t"
#define CORE_PARAMETER_BD_ADDR_TYPE_SIZE        1
#define CORE_PARAMETER_CID                      "cid"
#define CORE_PARAMETER_CID_SIZE                 2
#define CORE_PARAMETER_PSM                      "psm"
#define CORE_PARAMETER_PSM_SIZE                 2

#define L2CAP_CID_SIGNALING                        0x0001
#define L2CAP_CID_CONNECTIONLESS_CHANNEL           0x0002
#define L2CAP_CID_ATTRIBUTE_PROTOCOL               0x0004
#define L2CAP_CID_SIGNALING_LE                     0x0005
#define L2CAP_CID_SECURITY_MANAGER_PROTOCOL        0x0006
#define L2CAP_CID_BR_EDR_SECURITY_MANAGER          0x0007

#define BLUETOOTH_PSM_SDP                                                                0x0001
#define BLUETOOTH_PSM_RFCOMM                                                             0x0003
#define BLUETOOTH_PSM_TCS_BIN                                                            0x0005
#define BLUETOOTH_PSM_TCS_BIN_CORDLESS                                                   0x0007
#define BLUETOOTH_PSM_BNEP                                                               0x000F
#define BLUETOOTH_PSM_HID_CONTROL                                                        0x0011
#define BLUETOOTH_PSM_HID_INTERRUPT                                                      0x0013
#define BLUETOOTH_PSM_UPNP                                                               0x0015
#define BLUETOOTH_PSM_AVCTP                                                              0x0017
#define BLUETOOTH_PSM_AVDTP                                                              0x0019
#define BLUETOOTH_PSM_AVCTP_BROWSING                                                     0x001B
#define BLUETOOTH_PSM_UDI_C_PLANE                                                        0x001D
#define BLUETOOTH_PSM_ATT                                                                0x001F
#define BLUETOOTH_PSM_3DSP                                                               0x0021
#define BLUETOOTH_PSM_LE_PSM_IPSP                                                        0x0023
#define BLUETOOTH_PSM_OTS                                                                0x0025

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

s32 get_operation_idx(Operation *op);
s32 get_parameter_idx(Parameter *param);

Parameter *get_parameter(std::string name);
Operation *get_operation(std::string name);
void parse(const char *file);
void dump();


void dump_operation(Operation *op);