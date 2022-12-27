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
    reset();
}

u32 BTFuzzState::serialize(u8* buf)
{
    item_t* pItem = (item_t*)buf;
    // Serialize Connection States
    pItem->size = sizeof(hci_con) * vCon.size();
    memcpy(pItem->data, vCon.data(), pItem->size);

    // Serialize Cids
    pItem = (item_t*)&pItem->data[pItem->size];
    pItem->size = sizeof(u16) * vCid.size();
    memcpy(pItem->data, vCid.data(), pItem->size);

    // Serialize Psms
    pItem = (item_t*)&pItem->data[pItem->size];
    pItem->size = sizeof(u16) * vPsm.size();
    memcpy(pItem->data, vPsm.data(), pItem->size);

    return &pItem->data[pItem->size] - buf;
}

void BTFuzzState::deserialize(u8* buf)
{
    reset();
    // Deserialize Connection States
    item_t* pItem = (item_t*)buf;
    hci_con* pCon = (hci_con*)pItem->data;
    while((u8*)pCon - pItem->data < pItem->size){
        vCon.push_back(*pCon);
        pCon++;
    }

    // Deserialize Cids
    pItem = (item_t*)&pItem->data[pItem->size];
    u16 * pCid = (u16*)pItem->data;
    while((u8*)pCid - pItem->data < pItem->size){
        vCid.push_back(*pCid);
        sCid.insert(*pCid);
        pCid++;
    }

    // Deserialize Psms
    pItem = (item_t*)&pItem->data[pItem->size];
    u16 * pPsm = (u16*)pItem->data;
    while((u8*)pPsm - pItem->data < pItem->size){
        vPsm.push_back(*pPsm);
        sPsm.insert(*pPsm);
        pPsm++;
    }
}

void BTFuzzState::reset(){
    vCon.clear();
    if(Parameter* pCon = get_parameter(CORE_PARAMETER_HCI_HANDLE)){
        pCon->domain.clear();
    }

    sPsm.clear();
    vPsm.clear();
    sPsm.insert(psm_fixed.begin(), psm_fixed.end());
    vPsm.insert(vPsm.begin(), psm_fixed.begin(), psm_fixed.end());
    if(Parameter* pPsm = get_parameter(CORE_PARAMETER_PSM)){
        pPsm->domain.clear();
        for(u16 psm : sPsm){
            pPsm->domain.insert(bytes2vec(psm));
        }
    }

    sCid.clear();
    vCid.clear();
    sCid.insert(cid_fixed.begin(), cid_fixed.end());
    vCid.insert(vCid.begin(), cid_fixed.begin(), cid_fixed.end());
    if(Parameter* pCid = get_parameter(CORE_PARAMETER_CID)){
        pCid->domain.clear();
        for(u16 cid : sCid){
            pCid->domain.insert(bytes2vec(cid));
        }
    }
}

/// @brief Given an input item sequence and its corresponding output, append one new item to the sequence
/// @param items Input item sequence
/// @param size Size of \param items
/// @param out1 HCI output buffer
/// @param out2 API return values
u32 BTFuzzState::step_one(u8* items, u32 size, u8* hci, u8* rt)
{

}

void BTFuzzState::handle_cmd(hci_command_t* cmd)
{

}

void BTFuzzState::handle_evt(hci_event_t* evt)
{
    
}

void BTFuzzState::handle_op(operation_t* op)
{
    Operation* pOp = get_operation(op->id);
    if(pOp->name == CORE_OPERATION_L2CAP_CREATE_CHANNEL)
        handle_op_l2cap_create_channel(op);
}

void BTFuzzState::handle_evt_con_complete(hci_event_t* evt)
{

}

void BTFuzzState::handle_evt_le_con_complete(hci_event_t* evt)
{

}

void BTFuzzState::handle_op_l2cap_register_service(operation_t* op)
{

}

void BTFuzzState::handle_op_l2cap_create_channel(operation_t* op)
{

}