#include "BTFuzzState.h"
#include "BTFuzz.h"
#include <assert.h>
#include <string.h>

#include <iostream>
#include <map>
#include <set>
#include <vector>

#include "../../include/afl-fuzz.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "Hci.h"
#include "Operation.h"

using namespace std;

BTFuzz *BTFuzz::bt = nullptr;

std::vector<u16> psm_fixed = {
    BLUETOOTH_PSM_SDP,   BLUETOOTH_PSM_RFCOMM,      BLUETOOTH_PSM_TCS_BIN,        BLUETOOTH_PSM_TCS_BIN_CORDLESS,
    BLUETOOTH_PSM_BNEP,  BLUETOOTH_PSM_HID_CONTROL, BLUETOOTH_PSM_HID_INTERRUPT,  BLUETOOTH_PSM_UPNP,
    BLUETOOTH_PSM_AVCTP, BLUETOOTH_PSM_AVDTP,       BLUETOOTH_PSM_AVCTP_BROWSING, BLUETOOTH_PSM_UDI_C_PLANE,
    BLUETOOTH_PSM_ATT,   BLUETOOTH_PSM_3DSP,        BLUETOOTH_PSM_LE_PSM_IPSP,    BLUETOOTH_PSM_OTS};

vector<u16> cid_fixed = {
    L2CAP_CID_SIGNALING,    L2CAP_CID_CONNECTIONLESS_CHANNEL,    L2CAP_CID_ATTRIBUTE_PROTOCOL,
    L2CAP_CID_SIGNALING_LE, L2CAP_CID_SECURITY_MANAGER_PROTOCOL, L2CAP_CID_BR_EDR_SECURITY_MANAGER};

vector<u8> core_events = {BT_HCI_EVT_CONN_COMPLETE, BT_HCI_EVT_CONN_REQUEST, BT_HCI_EVT_DISCONNECT_COMPLETE};

vector<u16> core_commands = {BT_HCI_CMD_CREATE_CONN, BT_HCI_CMD_CREATE_CONN_CANCEL, BT_HCI_CMD_DISCONNECT,
                             BT_HCI_CMD_ACCEPT_CONN_REQUEST};


extern "C" void bt_restore_state()
{
    BTFuzz* bt = BTFuzz::get();
}

extern "C" void bt_reset_state()
{

}

extern "C" void bt_fuzz_one(u8* buf)
{
    BTFuzz::get()->fuzz_one(buf);
}

u32 BTFuzz::fuzz_one(u8 *buf)
{
    if (sema)
        return fuzz_one_sema(buf);
    else
        return fuzz_one_rand(buf);
}

// reply pending commands
u32 BTFuzz::fuzz_one_sema1(u8 *buf)
{
    if(pcmd.empty())
        return 0;

    u32 r = rand_below(pcmd.size());
    u32 s = rand_below(100);
    hci_command_t *cmd = (hci_command_t *)pcmd[r].data();

    item_t *pItem = (item_t *)buf;
    hci_event_t *pEvt = (hci_event_t *)pItem->data;
    bt_hci_evt_cmd_status *pStatus = (bt_hci_evt_cmd_status *)pEvt->param;
    pStatus->status = s >= 90 ? s % 10 : BT_HCI_ERR_SUCCESS;
    pStatus->ncmd = s % 10;
    pStatus->opcode = cmd->opcode;
    pEvt->flag = HCI_EVENT_PACKET;
    pEvt->len = sizeof(bt_hci_evt_cmd_status);
    pItem->size = sizeof(hci_event_t) + pEvt->len;

    if (cmd->opcode == BT_HCI_CMD_CREATE_CONN)
    {
        bt_hci_cmd_create_conn *c = (bt_hci_cmd_create_conn *)cmd->param;
        if (pStatus->status == BT_HCI_ERR_SUCCESS)
        {
            cur_state.add_pending_con(BD_ADDR_TYPE_ACL, c->bdaddr);
        }
        return pItem->size + sizeof(u32);
    }
    else if (cmd->opcode == BT_HCI_CMD_DISCONNECT)
    {
        bt_hci_cmd_disconnect *c = (bt_hci_cmd_disconnect *)cmd->param;
        if (pStatus->status == BT_HCI_ERR_SUCCESS)
        {
            cur_state.add_pending_discon(c->handle);
        }
        return pItem->size + sizeof(u32);
    }
    else if (cmd->opcode == BT_HCI_CMD_ACCEPT_CONN_REQUEST)
    {
        bt_hci_cmd_accept_conn_request *c = (bt_hci_cmd_accept_conn_request *)cmd->param;
        if (pStatus->status == BT_HCI_ERR_SUCCESS)
        {
            cur_state.add_pending_con(BD_ADDR_TYPE_ACL, c->bdaddr);
        }
        return pItem->size + sizeof(u32);
    }
    else if (cmd->opcode == BT_HCI_CMD_LE_CREATE_CONN || cmd->opcode == BT_HCI_CMD_LE_EXT_CREATE_CONN)
    {
        bt_hci_cmd_le_create_conn *c = (bt_hci_cmd_le_create_conn *)cmd->param;
        if (pStatus->status == BT_HCI_ERR_SUCCESS)
        {
            cur_state.add_pending_con(c->peer_addr_type, c->peer_addr);
        }
        return pItem->size + sizeof(u32);
    }
    else if (sStatusCmd.find(cmd->opcode) != sStatusCmd.end())
    {
        return pItem->size + sizeof(u32);
    }

    bt_hci_evt_cmd_complete *pCplt = (bt_hci_evt_cmd_complete *)pEvt->param;
    pCplt->ncmd = s % 10;
    pCplt->opcode = cmd->opcode;
    pEvt->len = sizeof(bt_hci_evt_cmd_complete);
    pItem->size = sizeof(hci_event_t) + pEvt->len;
    if (cmd->opcode == BT_HCI_CMD_CREATE_CONN_CANCEL)
    {
        bt_hci_cmd_create_conn_cancel *c = (bt_hci_cmd_create_conn_cancel *)cmd->param;
        cur_state.remove_pending_con(c->bdaddr);
    }
    else if (cmd->opcode == BT_HCI_CMD_LE_CREATE_CONN_CANCEL)
    {
        cur_state.remove_pending_le_con();
    }
    return pItem->size + sizeof(u32);
}

// core operations
u32 BTFuzz::fuzz_one_sema2(u8 *buf)
{
    u32 r = rand_below(5);
    item_t *pItem = (item_t *)buf;
    Operation *op;
    if (r == 0)
    {
        op = get_operation(CORE_OPERATION_GAP_CONNECT);
        op->generate();
    }
    else if (r == 1)
    {
        Operation *op = get_operation(CORE_OPERATION_GAP_DISCONNECT);
        op->generate();
    }
    else if (r == 2)
    {
        op = get_operation(CORE_OPERATION_GAP_CONNECT_CANCEL);
        op->generate();
    }
    else if (r == 3)
    {
        op = get_operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL);
        op->generate();
    }
    else if (r == 4)
    {
        Parameter *psm = get_parameter(CORE_PARAMETER_PSM);
        psm->bytes = 2;
        *(u16 *)psm->data = rand_below(UINT16_MAX);
        cur_state.add_psm(*(u16 *)psm->data);
        op = get_operation(CORE_OPERATION_L2CAP_REGISTER_SERVICE);
    }
    op->serialize(buf);
    return pItem->size + sizeof(u32);
}

// random operations
u32 BTFuzz::fuzz_one_sema3(u8 *buf)
{
    Operation *op;
    do
    {
        op = &operations[rand_below(operations.size())];
    } while (!op->generate());
    return op->serialize(buf);
}

// random events
u32 BTFuzz::fuzz_one_sema4(u8 *buf)
{
    u8 opcode = vEvt[rand_below(vEvt.size())];
    item_t *pItem = (item_t *)buf;
    hci_event_t *pEvt = (hci_event_t *)pItem->data;
    pEvt->len = 255;
    pEvt->opcode = opcode;
    pEvt->flag = HCI_EVENT_PACKET;
    rand_fill(pEvt->param, pEvt->len);
    pItem->size = pEvt->len + 3;
    return pItem->size + sizeof(u32);
}

// Core Events
u32 BTFuzz::fuzz_one_sema5(u8 *buf)
{
    u32 r = rand_below(10);
    u32 s = rand_below(100);
    item_t *pItem = (item_t *)buf;
    hci_event_t *pEvt = (hci_event_t *)pItem->data;
    pEvt->flag = HCI_EVENT_PACKET;

    if (r == 0 && !pcon.empty())
    {
        u32 i = rand_below(pcon.size());
        if(!is_le(pcon[i].type))
        {////////////////////////////////////////////////////
            bt_hci_evt_conn_complete *e = (bt_hci_evt_conn_complete *)pEvt->param;
            pEvt->opcode = BT_HCI_EVT_CONN_COMPLETE;
            pEvt->len = sizeof(bt_hci_evt_conn_complete);
            pItem->size = sizeof(hci_event_t) + pEvt->len;
            rand_fill((u8 *)e, sizeof(bt_hci_evt_conn_complete));
            e->status = s >= 90 ? s % 10 : BT_HCI_ERR_SUCCESS;
            memcpy(e->bdaddr, pcon[i].addr.addr, 6);
            if(e->status == BT_HCI_ERR_SUCCESS){
                pcon[i].handle = e->handle = ++max_handle;
                con.push_back(pcon[i]);
            }
        }
        else
        {
            bt_hci_evt_le_conn_complete* e = (bt_hci_evt_le_conn_complete*)&pEvt->param[1];
            pEvt->opcode = BT_HCI_EVT_LE_META_EVENT;
            pEvt->param[0] = BT_HCI_EVT_LE_CONN_COMPLETE;
            pEvt->len = sizeof(bt_hci_evt_le_conn_complete) + 1;
            pItem->size = sizeof(hci_event_t) + pEvt->len;
            rand_fill((u8*)e, sizeof(bt_hci_evt_le_conn_complete));
            e->status = s >= 90 ? s % 10 : BT_HCI_ERR_SUCCESS;
            e->peer_addr_type = pcon[i].type;
            e->role &= 1;
            memcpy(e->peer_addr, pcon[i].addr.addr, 6);
            if(e->status == BT_HCI_ERR_SUCCESS)
            {
                pcon[i].handle = e->handle = ++max_handle;
                con.push_back(pcon[i]);
            }
        }
        pcon.erase(pcon.begin() + i);
    }
    else if (r == 1 && !pdiscon.empty())
    {
        u32 i = rand_below(pdiscon.size());
        hci_con& c = get_con(pdiscon[i]);
        bt_hci_evt_disconnect_complete* e = (bt_hci_evt_disconnect_complete*)pEvt->param;
        e->handle = c.handle;
        e->status = s >= 90 ? s % 10 : BT_HCI_ERR_SUCCESS;
        e->reason = rand_below(UINT8_MAX);
        pEvt->opcode = BT_HCI_EVT_DISCONNECT_COMPLETE;
        pEvt->len = sizeof(bt_hci_evt_disconnect_complete);
        pItem->size = sizeof(hci_event_t) + pEvt->len;
        if(e->status == BT_HCI_ERR_SUCCESS){
            remove_con(c.handle);
        }
        pdiscon.erase(pdiscon.begin() + i);
    }
    else if (r == 2)
    {
        bt_hci_evt_conn_request* e = (bt_hci_evt_conn_request*)pEvt->param;
        pEvt->opcode = BT_HCI_EVT_CONN_REQUEST;
        pEvt->len = sizeof(bt_hci_evt_conn_request);
        pItem->size = sizeof(hci_event_t) + pEvt->len;
        rand_fill((u8*)e, sizeof(bt_hci_evt_conn_request));
        e->link_type &= 1;
    }
    return pItem->size + sizeof(u32);
}

u32 BTFuzz::fuzz_one_sema(u8 *buf)
{
    u32 r = rand_below(100);
    // Reply Pending Commands
    if(r < 80){
       u32 res = fuzz_one_sema1(buf);
       if(!res) return  res;
    }
    
    // Core Operations
    if(r < 20)
        return fuzz_one_sema2(buf);
    // Randome Operations
    else if(r < 40)
        return fuzz_one_sema3(buf);
    // Random Events
    else if(r < 60)
        return fuzz_one_sema4(buf);
    // Core Events
    else
        return fuzz_one_sema5(buf);
}

u32 BTFuzz::fuzz_one_rand(u8 *buf)
{
    u32 rand = rand_below(6);
    if (rand < 2)
    {
        Operation *op = get_operation(rand_below(operations.size()));
        op->generate();
        return op->serialize(buf);
    }
    else if (rand < 4)
    {
        item_t *pItem = (item_t *)buf;
        hci_event_t *pEvt = (hci_event_t *)pItem->data;
        pEvt->flag = HCI_EVENT_PACKET;
        pEvt->len = 255;
        pEvt->opcode = vEvt[rand_below(vEvt.size())];
        rand_fill(pEvt->param, pEvt->len);
        pItem->size = pEvt->len + 3;
        return pItem->size + sizeof(u32);
    }
}
