#include "../../include/afl-fuzz.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "bt-harness.h"
#include "bt-fuzz.h"

#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <string.h>

using namespace std;

BTFuzzState* BTFuzzState::bt = nullptr;

extern "C" void reset_bt_fuzz_state()
{
    BTFuzzState::get()->reset();
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
    pending_con.emplace(bd_addr, *(bd_addr_type_t*)pa_hdr2->data);
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
    pending_discon.emplace(*(hci_con_handle_t*)pa_hdr->data[0]);
    return op_hdr->size + sizeof(u32);
}

u32 BTFuzzState::generate_l2cap_create_channel(u8* buf)
{  
    operation_header* op_hdr = (operation_header*)buf;
    parameter_header* pa_hdr = (parameter_header*)(buf + sizeof(operation_header));

    if(choose_bd_addr(&pa_hdr->data[0]) == 0)
        return 0;
    
    op_hdr->operation_idx = get_parameter(CORE_OPERATION_L2CAP_REGISTER_SERVICE)->idx;
    op_hdr->arg_in_cnt = 1;
    op_hdr->flag = OPERATION;
    op_hdr->size = CORE_OPERATION_L2CAP_REGISTER_SERVICE_SIZE;
    pa_hdr->arg_idx = get_parameter(CORE_PARAMETER_BD_ADDR)->idx;
    pa_hdr->arg_len = CORE_PARAMETER_BD_ADDR_SIZE;
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

extern "C" void generate_random_operation(u8 *out_buf)
{
    Operation *op;
    u32 idx, cnt, arg_in_cnt;
    BTFuzzState* bt = BTFuzzState::get();
    cnt = bt->rand_below(operation_list.size() - get_core_operation_num());
    for(u32 n=operation_list.size(), idx=0;idx<n;idx++){
        if(is_core_operation(operation_list[idx]->name))
            continue;
        if(cnt == 0){
            op = operation_list[idx];
            break;
        }
        cnt--;
    }

    arg_in_cnt = op->inputs.size();

    operation_header *hdr = (operation_header *)out_buf;
    hdr->flag = OPERATION;
    hdr->operation_idx = idx;
    hdr->arg_in_cnt = arg_in_cnt;

    u32 i = sizeof(operation_header);
    for (Parameter *param : op->inputs)
    {
        parameter_header *param_hdr = (parameter_header *)(out_buf + i);
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
        else if(is_core_parameter(param->name))
        {
            param_hdr->arg_idx = get_parameter_idx(param);
            param_hdr->arg_len = bt->core_parameter_choose(out_buf + i + sizeof(parameter_header), param->name);
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
}
