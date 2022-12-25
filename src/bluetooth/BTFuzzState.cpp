#include "../../include/afl-fuzz.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "Operation.h"
#include "BTFuzzState.h"

#include <assert.h>
#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <string.h>

using namespace std;

BTFuzzState* BTFuzzState::bt = nullptr;

string core_parameters[] = {
    CORE_PARAMETER_HCI_HANDLE,
    CORE_PARAMETER_CID,
    CORE_PARAMETER_PSM
};

string core_operations[] = {
    CORE_OPERATION_GAP_CONNECT,
    CORE_OPERATION_GAP_DISCONNECT,       
    CORE_OPERATION_L2CAP_CREATE_CHANNEL, 
    CORE_OPERATION_L2CAP_REGISTER_SERVICE
};

std::vector<u16> psm_fixed = {
    BLUETOOTH_PSM_SDP,
    BLUETOOTH_PSM_RFCOMM,
    BLUETOOTH_PSM_TCS_BIN,
    BLUETOOTH_PSM_TCS_BIN_CORDLESS,
    BLUETOOTH_PSM_BNEP,
    BLUETOOTH_PSM_HID_CONTROL,
    BLUETOOTH_PSM_HID_INTERRUPT,
    BLUETOOTH_PSM_UPNP,
    BLUETOOTH_PSM_AVCTP,
    BLUETOOTH_PSM_AVDTP,
    BLUETOOTH_PSM_AVCTP_BROWSING,
    BLUETOOTH_PSM_UDI_C_PLANE,
    BLUETOOTH_PSM_ATT,
    BLUETOOTH_PSM_3DSP,
    BLUETOOTH_PSM_LE_PSM_IPSP,
    BLUETOOTH_PSM_OTS
};

vector<u16> cid_fixed = {
    L2CAP_CID_SIGNALING,
    L2CAP_CID_CONNECTIONLESS_CHANNEL,
    L2CAP_CID_ATTRIBUTE_PROTOCOL,
    L2CAP_CID_SIGNALING_LE,
    L2CAP_CID_SECURITY_MANAGER_PROTOCOL,
    L2CAP_CID_BR_EDR_SECURITY_MANAGER
};


extern "C" void reset_bt_fuzz_state()
{
    BTFuzzState::get()->reset();
}

BTFuzzState::BTFuzzState()
{
    dev_urandom_fd = open("/dev/urandom", O_RDONLY);
    read(dev_urandom_fd, &rand_seed, sizeof(rand_seed));
}

void BTFuzzState::reset(){
    con_s.clear();
    psm_s.clear();
    psm_s.insert(psm_fixed.begin(), psm_fixed.end());
    cid_s.clear();
    cid_s.insert(cid_fixed.begin(), cid_fixed.end());
}

Parameter* BTFuzzState::generate_core_parameter(Parameter* p){
    if(p->name == CORE_PARAMETER_HCI_HANDLE)
        return generate_hci_con_handle();
    else if(p->name == CORE_PARAMETER_PSM)
        return generate_l2cap_psm();
    else if(p->name == CORE_PARAMETER_CID)
        return generate_l2cap_cid();
    else
        return p;
}

Parameter* BTFuzzState::generate_hci_con_handle()
{
    if(con_s.empty())
        return nullptr;

    u32 n = rand_below(con_s.size());
    Parameter* p = get_parameter(CORE_PARAMETER_HCI_HANDLE);
    auto iter = con_s.begin();
    for(;n>0;n--) ++iter;
    *(u16*)p->data = iter->first;
    return p;
}

Parameter* BTFuzzState::generate_l2cap_psm()
{
    u32 n = rand_below(psm_s.size());
    Parameter* p = get_parameter(CORE_PARAMETER_PSM);
    auto iter = psm_s.begin();
    for(;n>0;n--) ++iter;
    *(u16*)p->data = *iter;
    return p;
}

Parameter* BTFuzzState::generate_l2cap_cid()
{
    u32 n = rand_below(psm_s.size());
    Parameter* p = get_parameter(CORE_PARAMETER_CID);
    auto iter = psm_s.begin();
    for(;n>0;n--) ++iter;
    *(u16*)p->data = *iter;
    return p;
}

Operation* BTFuzzState::generate_gap_connect()
{
    // bd_addr, bd_addr_type
    Operation* op = get_operation(CORE_OPERATION_GAP_CONNECT);
    Parameter* bd_addr = op->param(0);
    Parameter* bd_addr_type = op->param(1);    
    memcpy(bd_addr->data, addr.bd_addr, CORE_PARAMETER_BD_ADDR_SIZE);
    memcpy(bd_addr_type->data, &type, CORE_PARAMETER_BD_ADDR_TYPE_SIZE);
    return op;
}

Operation* BTFuzzState::generate_gap_connect_cancel()
{
    return get_operation(CORE_OPERATION_GAP_CONNECT_CANCEL);
}

u32 BTFuzzState::generate_hci_con_complete_event(u8* buf)
{

}

u32 BTFuzzState::generate_hci_le_con_complete_event(u8* buf)
{

}

Operation* BTFuzzState::generate_gap_disconnect()
{
    Operation* op = get_operation(CORE_OPERATION_GAP_DISCONNECT);
    return generate_hci_con_handle() ? op : nullptr;
}

Operation* BTFuzzState::generate_l2cap_create_channel()
{  
    // bd_addr, psm
    Operation* op = get_operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL);
    generate_bd_addr();
    generate_l2cap_psm();
    return op;
}

Operation* BTFuzzState::generate_l2cap_register_service()
{
    //psm, security_level
    u16 psm;
    u8 level = rand_below(security_level.size());
    Operation* op = get_operation(CORE_OPERATION_L2CAP_REGISTER_SERVICE);
    Parameter* pPsm = op->param(0);
    Parameter* pLevel = op->param(1);

    while(psm_s.find(psm) != psm_s.end()) 
        psm = rand_below(UINT16_MAX);

    *(u16*)pPsm->data = psm;
    *pLevel->data = level;
    psm_s.emplace(psm);
    return op;
}

Operation* BTFuzzState::generate_random_operation(u32 id, bool sema)
{
    Operation* op = get_operation(id);
    for (Parameter *p : op->inputs)
    {
       j if(sema && generate_core_parameter(p) == nullptr)
            return nullptr;
        else if(p->isEnum)
            p->data[0] = rand_below(p->enum_domain.size());
        else if(!p->domain.empty()){
            u32 i = rand_below(p->domain.size());
            memcpy(p->data, p->domain[i].data(), p->bytes);
        }else{
            if(p->max_bytes == p->min_bytes)
                p->bytes = p->max_bytes;
            else
                p->bytes = p->min_bytes + rand_below(p->max_bytes-p->min_bytes);
            rand_fill(p->data, p->bytes);
        }
    }
}


