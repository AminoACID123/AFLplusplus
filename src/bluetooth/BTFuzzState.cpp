#include "../../include/afl-fuzz.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "bt-harness.h"
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
    CORE_PARAMETER_BD_ADDR,
    CORE_PARAMETER_HCI_HANDLE,
    CORE_PARAMETER_BD_ADDR_TYPE,
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

void BTFuzzState::reset(){
    bd_addr_s.clear();
    hci_con_handle_m.clear();
    psm_s.clear();
    psm_s.insert(psm_fixed.begin(), psm_fixed.end());
    cid_s.clear();
    cid_s.insert(cid_fixed.begin(), cid_fixed.end());
}

u32 BTFuzzState::core_parameter_choose(u8* buf, string name){
    if(name == CORE_PARAMETER_BD_ADDR)
        return choose_bd_addr(buf);
    else if(name == CORE_PARAMETER_BD_ADDR_TYPE)
        return choose_bd_addr_type(buf);
    else if(name == CORE_PARAMETER_HCI_HANDLE)
        return choose_hci_con_handle(buf);
    else if(name == CORE_PARAMETER_PSM)
        return choose_l2cap_psm(buf);
    else if(name == CORE_PARAMETER_CID)
        return choose_l2cap_cid(buf);
}

u32 BTFuzzState::choose_bd_addr(u8* buf)
{
    if(bd_addr_s.empty())
        return 0;
    u32 n = rand_below(bd_addr_s.size());
    auto iter = bd_addr_s.begin();
    for(;n>0;n--) ++iter;
    memcpy(buf, &iter->bd_addr[0], 6);
    return CORE_PARAMETER_BD_ADDR_SIZE;
}

u32 BTFuzzState::choose_bd_addr_type(u8* buf)
{
    u32 m = sizeof(bd_addr_type_s) / sizeof(bd_addr_type_t);
    u32 n = rand_below(m);
    *buf = bd_addr_type_s[n];
    return CORE_PARAMETER_BD_ADDR_TYPE_SIZE;
}

u32 BTFuzzState::choose_hci_con_handle(u8* buf)
{
    if(hci_con_handle_m.empty())
        return 0;
    u32 n = rand_below(hci_con_handle_m.size());
    auto iter = hci_con_handle_m.begin();
    for(;n>0;n--) ++iter;
    memcpy(buf, &iter->first, 2);
    return CORE_PARAMETER_HCI_HANDLE_SIZE;
}

u32 BTFuzzState::choose_l2cap_psm(u8* buf)
{
    if(psm_s.empty())
        return 0;
    u32 n = rand_below(psm_s.size());
    auto iter = psm_s.begin();
    for(;n>0;n--) ++iter;
    *(u16*)buf = *iter;
    return CORE_PARAMETER_PSM_SIZE;
}

u32 BTFuzzState::choose_l2cap_cid(u8* buf)
{
    if(psm_s.empty())
        return 0;
    u32 n = rand_below(psm_s.size());
    auto iter = psm_s.begin();
    for(;n>0;n--) ++iter;
    *(u16*)buf = *iter;
    return CORE_PARAMETER_CID_SIZE;
}

u32 BTFuzzState::generate_gap_connect(u8* buf)
{
    bd_addr_t bd_addr;
    for(u32 i=0;i<6;i++)
        bd_addr.bd_addr[i] = rand_below(UINT8_MAX);
    
    operation_header* op_hdr = (operation_header*)buf;
    parameter_header* pa_hdr1 = (parameter_header*)(buf + sizeof(operation_header));
    parameter_header* pa_hdr2 = (parameter_header*)(buf + sizeof(operation_header) + sizeof(parameter_header) + CORE_PARAMETER_BD_ADDR_SIZE);
    Operation* op = get_operation(CORE_OPERATION_GAP_CONNECT);
    op_hdr->flag = OPERATION;
    op_hdr->operation_idx = op->idx;
    op_hdr->arg_in_cnt = 2;
    op_hdr->size = CORE_OPERATION_GAP_CONNECT_SIZE;
    pa_hdr1->arg_idx = get_parameter(CORE_PARAMETER_BD_ADDR)->idx;
    pa_hdr1->arg_len = CORE_PARAMETER_BD_ADDR_SIZE;
    pa_hdr2->arg_idx = get_parameter(CORE_PARAMETER_BD_ADDR_TYPE)->idx;
    pa_hdr2->arg_len = CORE_PARAMETER_BD_ADDR_TYPE_SIZE;
    memcpy(pa_hdr1->data, &bd_addr.bd_addr[0], 6);
    choose_bd_addr_type(pa_hdr2->data);
    return op_hdr->size + sizeof(u32);
}

u32 BTFuzzState::generate_gap_connect_cancel(u8* buf)
{
    operation_header* op_hdr = (operation_header*)buf;
    parameter_header* pa_hdr = (parameter_header*)(buf + sizeof(operation_header)); 
    Operation* op = get_operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL);
    op_hdr->flag = OPERATION;
    op_hdr->operation_idx = op->idx;
    op_hdr->arg_in_cnt = 0;
    op_hdr->size = CORE_OPERATION_GAP_CONNECT_CANCEL_SIZE;
    return op_hdr->size + sizeof(u32);
}

u32 BTFuzzState::generate_hci_con_complete_event(u8* buf)
{

}

u32 BTFuzzState::generate_hci_le_con_complete_event(u8* buf)
{

}

u32 BTFuzzState::generate_gap_disconnect(u8* buf)
{
    operation_header* op_hdr = (operation_header*)buf;
    parameter_header* pa_hdr = (parameter_header*)(buf + sizeof(operation_header));
    Operation* op = get_operation(CORE_OPERATION_GAP_DISCONNECT);

    if(choose_hci_con_handle(&pa_hdr->data[0]) == 0)
        return 0;
    op_hdr->flag = OPERATION;
    op_hdr->arg_in_cnt = 1;
    op_hdr->operation_idx = op->idx;
    op_hdr->size = CORE_OPERATION_GAP_DISCONENCT_SIZE;

    pa_hdr->arg_idx = get_parameter(CORE_PARAMETER_HCI_HANDLE)->idx;
    pa_hdr->arg_len = CORE_PARAMETER_HCI_HANDLE_SIZE;
    return op_hdr->size + sizeof(u32);
}

u32 BTFuzzState::generate_l2cap_create_channel(u8* buf)
{  
    operation_header* op_hdr = (operation_header*)buf;
    parameter_header* pa_hdr1 = (parameter_header*)(buf + sizeof(operation_header));
    parameter_header* pa_hdr2 = (parameter_header*)((u8*)pa_hdr1 + sizeof(parameter_header) + CORE_PARAMETER_BD_ADDR_SIZE);

    if(choose_bd_addr(&pa_hdr1->data[0]) == 0 || choose_l2cap_psm(&pa_hdr2->data[0]) == 0)
        return 0;
    
    op_hdr->operation_idx = get_parameter(CORE_OPERATION_L2CAP_REGISTER_SERVICE)->idx;
    op_hdr->arg_in_cnt = 2;
    op_hdr->flag = OPERATION;
    op_hdr->size = CORE_OPERATION_L2CAP_CREATE_CHANNEL_SIZE;

    pa_hdr1->arg_idx = get_parameter(CORE_PARAMETER_BD_ADDR)->idx;
    pa_hdr1->arg_len = CORE_PARAMETER_BD_ADDR_SIZE;
    pa_hdr2->arg_idx = get_parameter(CORE_PARAMETER_PSM)->idx;
    pa_hdr2->arg_len = CORE_PARAMETER_PSM_SIZE;
    
    return op_hdr->size + sizeof(u32);
}

u32 BTFuzzState::generate_l2cap_register_service(u8* buf)
{
    operation_header* op_hdr = (operation_header*)buf;
    parameter_header* pa_hdr = (parameter_header*)(buf + sizeof(operation_header));

    u16 psm = rand_below(UINT16_MAX);

    op_hdr->flag = OPERATION;
    op_hdr->arg_in_cnt = 1;
    op_hdr->operation_idx = get_operation(CORE_OPERATION_L2CAP_REGISTER_SERVICE)->idx;
    op_hdr->size = CORE_OPERATION_L2CAP_REGISTER_SERVICE_SIZE;

    pa_hdr->arg_idx = get_parameter(CORE_PARAMETER_PSM)->idx;
    pa_hdr->arg_len = CORE_PARAMETER_PSM_SIZE;
    *(u16*)pa_hdr->data = psm;
    psm_s.emplace(psm);
    return op_hdr->size + sizeof(u32);
}

/// idx == -1: generate random noncore operation
/// o.w.: generate operation[idx]
extern "C" u32 generate_random_operation(s32 idx, u8 *out_buf)
{
    Operation *op;
    BTFuzzState* bt = BTFuzzState::get();
    u32 cnt, arg_in_cnt;
    operation_header *hdr = (operation_header *)out_buf;

    if(idx == -1)
    {
        cnt = bt->rand_below(operation_list.size() - get_core_operation_num());
        for(u32 n=operation_list.size(), i=0;i<n;i++){
            if(is_core_operation(operation_list[i]->name))
                continue;
            if(cnt == 0){
                op = operation_list[i];
                break;
            }
            cnt--;
        }
    }
    else
    {
        assert(idx >= 0 && idx < operation_list.size());
        op = operation_list[idx];
    }

    arg_in_cnt = op->inputs.size();

    hdr->flag = OPERATION;
    hdr->operation_idx = idx;
    hdr->arg_in_cnt = arg_in_cnt;

    u32 i = sizeof(operation_header);
    for (Parameter *param : op->inputs)
    {
        parameter_header *param_hdr = (parameter_header *)(out_buf + i);
        bool c = is_core_parameter(param->name);
        if (param->name == "data")
        {
            u32 rand_len = bt->rand_below(BT_MAX_PARAM_SIZE);
            u32 len = (param->bytes == -1 ? 1 + rand_len : param->bytes);
            u8* param_buf = new u8[len];
            param_hdr->arg_len = len;
            param_hdr->arg_idx = 0;
            memcpy(out_buf + i + sizeof(parameter_header), param_buf, len);
            i += (sizeof(parameter_header) + len);
            delete[] param_buf;
        }
        else if(c)
        {
            if(idx == -1){
                param_hdr->arg_idx = get_parameter_idx(param);
                param_hdr->arg_len = bt->core_parameter_choose(out_buf + i + sizeof(parameter_header), param->name);
                if(param_hdr->arg_len == 0)
                    return 0;
            }else{
                param_hdr->arg_idx = get_parameter_idx(param);
                param_hdr->arg_len = param->bytes;
            }
            i += (sizeof(parameter_header) + param->bytes);
        }
        else
        {
            param_hdr->arg_idx = get_parameter_idx(param);
            if (param->isEnum){
                param_hdr->arg_len = 1;
                out_buf[i + sizeof(parameter_header)] = bt->rand_below(param->enum_domain.size());
            }
            else{
                u32 j = bt->rand_below(param->domain.size());
                param_hdr->arg_len = param->bytes;
                memcpy(out_buf + i + sizeof(parameter_header), param->domain[j].data(), param->domain[j].size());
            }
            i += (sizeof(parameter_header) + param->bytes);
        }
    }
    hdr->size = i - 4;
    return hdr->size;
}
