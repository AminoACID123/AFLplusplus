#ifndef BTFUZZ_ATT_H
#define BTFUZZ_ATT_H

#include "btfuzz_state.h"
#include "common/type.h"

#include <stdlib.h>

#define btfuzz_alloc_att(handle, opcode, len) \
    u32 total_len = sizeof(bt_hci_acl_hdr) + sizeof(bt_l2cap_hdr) + sizeof(bt_l2cap_att_hdr) + len; \
    btfuzz->acl_buf_out = realloc(btfuzz->acl_buf_out, total_len) 
    
void send_att_exchange_mtu_req(u16 handle, u16 mtu);

void send_att_write_req(u16 handle, u16 att_handle, void* data, u32 data_len);

#endif