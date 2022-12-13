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
    if(name == "bd_addr_t")
        return choose_bd_addr(buf);
    else if(name == "bd_addr_type_t")
        return choose_bd_addr_type(buf);
    else if(name == "hci_con_handle_t")
        return choose_hci_con_handle(buf);
    else if(name == "psm")
        return choose_l2cap_psm(buf);
    else if(name == "cid")
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
    return 6;
}

u32 BTFuzzState::choose_bd_addr_type(u8* buf)
{
    u32 m = sizeof(bd_addr_type_s) / sizeof(bd_addr_type_t);
    u32 n = rand_below(m);
    *buf = bd_addr_type_s[n];
    return 1;
}

u32 BTFuzzState::choose_hci_con_handle(u8* buf)
{
    if(hci_con_handle_m.empty())
        return 0;
    u32 n = rand_below(hci_con_handle_m.size());
    auto iter = hci_con_handle_m.begin();
    for(;n>0;n--) ++iter;
    memcpy(buf, &iter->first, 2);
    return 2;
}

u32 BTFuzzState::choose_l2cap_psm(u8* buf)
{
    
}

u32 BTFuzzState::choose_l2cap_cid(u8* buf)
{
    u32 m = l2cap_remote_cid_s.size() + l2cap_local_cid_s.size();
    if(m == 0) return 0;
    u32 n = rand_below(m);
    if(n < l2cap_local_cid_s.size()){
        auto iter = l2cap_local_cid_s.begin();
        for(;n>0;n--) ++iter;
        *(u16*)buf = *iter;
    }else{
        n -= l2cap_local_cid_s.size();
        auto iter = l2cap_remote_cid_s.begin();
        for(;n>0;n--) ++iter;
        *(u16*)buf = *iter;
    }
    return 2;
}

void BTFuzzState::generate_gap_connect()
{

}

void BTFuzzState::generate_hci_con_complete_event()
{

}

void BTFuzzState::generate_hci_le_con_complete_event()
{

}

void BTFuzzState::generate_gap_disconnect()
{

}

void BTFuzzState::generate_l2cap_create_channel()
{

}

void BTFuzzState::generate_l2cap_register_service()
{

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

    struct operation_header{
        u32 size;
        u8 flag;
        u32 operation_idx;
        u32 arg_in_cnt;
    } __attribute__((packed));

    struct parameter_header{
        u32 arg_idx;
        u32 arg_len;
    } __attribute__((packed));

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
