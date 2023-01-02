#include "BTFuzzState.h"
#include "../../include/afl-fuzz.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "Hci.h"
#include "Operation.h"

#include <assert.h>
#include <iostream>
#include <map>
#include <set>
#include <string.h>
#include <vector>

using namespace std;

BTFuzzState *BTFuzzState::bt = nullptr;

std::vector<u16> psm_fixed = {
    BLUETOOTH_PSM_SDP,   BLUETOOTH_PSM_RFCOMM,      BLUETOOTH_PSM_TCS_BIN,        BLUETOOTH_PSM_TCS_BIN_CORDLESS,
    BLUETOOTH_PSM_BNEP,  BLUETOOTH_PSM_HID_CONTROL, BLUETOOTH_PSM_HID_INTERRUPT,  BLUETOOTH_PSM_UPNP,
    BLUETOOTH_PSM_AVCTP, BLUETOOTH_PSM_AVDTP,       BLUETOOTH_PSM_AVCTP_BROWSING, BLUETOOTH_PSM_UDI_C_PLANE,
    BLUETOOTH_PSM_ATT,   BLUETOOTH_PSM_3DSP,        BLUETOOTH_PSM_LE_PSM_IPSP,    BLUETOOTH_PSM_OTS};

vector<u16> cid_fixed = {
    L2CAP_CID_SIGNALING,    L2CAP_CID_CONNECTIONLESS_CHANNEL,    L2CAP_CID_ATTRIBUTE_PROTOCOL,
    L2CAP_CID_SIGNALING_LE, L2CAP_CID_SECURITY_MANAGER_PROTOCOL, L2CAP_CID_BR_EDR_SECURITY_MANAGER};

extern "C" void reset_bt_fuzz_state()
{
    BTFuzzState::get()->reset();
}

BTFuzzState::BTFuzzState()
{
    reset();
}

u32 BTFuzzState::serialize(u8 *buf)
{
    item_t *pItem = (item_t *)buf;
    // Serialize Connection States
    pItem->size = sizeof(hci_con) * vCon.size();
    memcpy(pItem->data, vCon.data(), pItem->size);

    // Serialize Cids
    pItem = (item_t *)&pItem->data[pItem->size];
    pItem->size = sizeof(u16) * vCid.size();
    memcpy(pItem->data, vCid.data(), pItem->size);

    // Serialize Psms
    pItem = (item_t *)&pItem->data[pItem->size];
    pItem->size = sizeof(u16) * vPsm.size();
    memcpy(pItem->data, vPsm.data(), pItem->size);

    return &pItem->data[pItem->size] - buf;
}

void BTFuzzState::deserialize(u8 *buf)
{
    // Deserialize Connection States
    item_t *pItem = (item_t *)buf;
    hci_con *pCon = (hci_con *)pItem->data;
    while ((u8 *)pCon - pItem->data < pItem->size)
    {
        vCon.push_back(*pCon);
        pCon++;
    }

    // Deserialize Cids
    pItem = (item_t *)&pItem->data[pItem->size];
    u16 *pCid = (u16 *)pItem->data;
    while ((u8 *)pCid - pItem->data < pItem->size)
    {
        vCid.push_back(*pCid);
        sCid.insert(*pCid);
        pCid++;
    }

    // Deserialize Psms
    pItem = (item_t *)&pItem->data[pItem->size];
    u16 *pPsm = (u16 *)pItem->data;
    while ((u8 *)pPsm - pItem->data < pItem->size)
    {
        vPsm.push_back(*pPsm);
        sPsm.insert(*pPsm);
        pPsm++;
    }
}

void BTFuzzState::reset()
{
    vCon.clear();

    sPsm.clear();
    vPsm.clear();
    sPsm.insert(psm_fixed.begin(), psm_fixed.end());
    vPsm.insert(vPsm.begin(), psm_fixed.begin(), psm_fixed.end());

    sCid.clear();
    vCid.clear();
    sCid.insert(cid_fixed.begin(), cid_fixed.end());
    vCid.insert(vCid.begin(), cid_fixed.begin(), cid_fixed.end());

    sync();
}

void BTFuzzState::sync()
{
    if (Parameter *pCon = get_parameter(CORE_PARAMETER_HCI_HANDLE))
    {
        pCon->domain.clear();
    }
    if (Parameter *pPsm = get_parameter(CORE_PARAMETER_PSM))
    {
        pPsm->domain.clear();
        for (u16 psm : sPsm)
        {
            pPsm->domain.insert(bytes2vec(psm));
        }
    }
    if (Parameter *pCid = get_parameter(CORE_PARAMETER_CID))
    {
        pCid->domain.clear();
        for (u16 cid : sCid)
        {
            pCid->domain.insert(bytes2vec(cid));
        }
    }
}

u32 BTFuzzState::step_one(u8 *items, u32 size)
{
    item_t *pItem = (item_t *)items;
    item_t *pItemIn;
    item_t *pItemOut = (item_t *)hci;
    BT_ItemForEach3(pItem, items, size)
    {
        pItemIn = pItem;
    }

    // handle_item(pItemIn);
    switch (pItemIn->data[0])
    {
    case OPERATION:
        handle_op((operation_t *)pItemIn->data);
        break;
    case HCI_EVENT_PACKET:
        handle_evt((hci_event_t *)pItemIn->data);
        break;
    }

    BT_ItemForEach2(pItemOut, hci)
    {
        switch (pItemOut->data[0])
        {
        case HCI_COMMAND_DATA_PACKET:
            handle_cmd((hci_command_t *)pItemOut->data);
            break;
        case HCI_ACL_DATA_PACKET:
            break;
        }
    }
}

u32 BTFuzzState::fuzz_one(u8 *buf)
{
    u32 r = rand_below(100);
    if (r <= 100)
    {
        Operation *op = get_operation(rand_below(operations.size()));
        op->generate();
        return op->serialize(buf);
    }
}

void BTFuzzState::handle_cmd(hci_command_t *cmd)
{
    switch (cmd->opcode)
    {
    case BT_HCI_CMD_CREATE_CONN:
        /* code */
        break;
    case BT_HCI_CMD_CREATE_CONN_CANCEL:
        break;
    case BT_HCI_CMD_DISCONNECT:
        break;
    default:
        break;
    }
}

void BTFuzzState::handle_evt(hci_event_t *evt)
{
}

void BTFuzzState::handle_op(operation_t *op)
{
    Operation *pOp = get_operation(op->id);
    if (pOp->name == CORE_OPERATION_L2CAP_CREATE_CHANNEL)
        handle_op_l2cap_create_channel(op);
    else if (pOp->name == CORE_OPERATION_L2CAP_REGISTER_SERVICE)
        handle_op_l2cap_register_service(op);
}

void BTFuzzState::handle_evt_con_complete(hci_event_t *evt)
{
}

void BTFuzzState::handle_evt_le_con_complete(hci_event_t *evt)
{
}

void BTFuzzState::handle_op_l2cap_create_channel(operation_t *op)
{
    u16 *cid = (u16 *)rt;
    vCid.push_back(*cid);
    sPsm.insert(*cid);
}

void BTFuzzState::handle_op_l2cap_register_service(operation_t *op)
{
    Parameter *psm = get_parameter(CORE_PARAMETER_PSM);
    get_operation(op->id)->deserialize(op);
    vPsm.push_back(*(u16 *)psm->data);
    sPsm.insert(*(u16 *)psm->data);
}
