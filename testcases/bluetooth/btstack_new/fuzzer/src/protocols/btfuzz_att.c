#include "btfuzz.h"
#include "protocols/btfuzz_att.h"
#include "common/bluetooth.h"
#include "common/transport.h"

#include <alloca.h>



#define prepare_att(type, opc) \
    cast_define(bt_hci_acl_hdr*, acl, btfuzz->acl_buf_out); \
    cast_define(bt_l2cap_hdr*, l2cap, acl->data); \
    cast_define(bt_l2cap_att_hdr*,att, l2cap->data); \
    cast_define(type, req, att->param); \
    att->opcode = opc; \
    l2cap->cid = L2CAP_CID_ATTRIBUTE_PROTOCOL;

void send_att_packet(u16 handle, u8 opcode, void* data, u32 len)
{

}


void send_att_exchange_mtu_req(u16 handle, u16 mtu)
{
    // cast_define(bt_hci_acl_hdr*, acl, btfuzz->acl_buf_out);
    // cast_define(bt_l2cap_hdr*, l2cap, acl->data);
    // cast_define(bt_l2cap_att_hdr*,att, l2cap->data);
    // cast_define(att_exchange_mtu_request*, req, att->param);

    prepare_att(att_exchange_mtu_request*, ATT_EXCHANGE_MTU_REQUEST)
    req->mtu = mtu;
    l2cap->len = sizeof(bt_l2cap_att_hdr) + sizeof(att_exchange_mtu_request);
    acl->handle = handle | ACL_PB_FIRST;
    acl->len = sizeof(bt_l2cap_hdr) + l2cap->len;

    send_packet(HCI_ACL_DATA_PACKET, btfuzz->acl_buf_out, sizeof(bt_hci_acl_hdr) + acl->len);
}

void send_att_write_req(u16 handle, u16 att_handle, void* data, u32 data_len)
{
    prepare_att(att_write_request*, ATT_WRITE_REQUEST)

    data_len = 2;
    req->handle = att_handle;
    memcpy(req->data, data, data_len);
    l2cap->len = sizeof(bt_l2cap_att_hdr) + sizeof(att_write_request) + data_len;
    acl->handle = handle | ACL_PB_FIRST;
    acl->len = sizeof(bt_l2cap_hdr) + l2cap->len;

    send_packet(HCI_ACL_DATA_PACKET, btfuzz->acl_buf_out, sizeof(bt_hci_acl_hdr) + acl->len);
}