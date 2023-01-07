#include "BTFuzzState.h"

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

BTFuzzState *BTFuzzState::bt = nullptr;

std::vector<u16> psm_fixed = {BLUETOOTH_PSM_SDP,
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
                              BLUETOOTH_PSM_OTS};

vector<u16> cid_fixed = {L2CAP_CID_SIGNALING,
                         L2CAP_CID_CONNECTIONLESS_CHANNEL,
                         L2CAP_CID_ATTRIBUTE_PROTOCOL,
                         L2CAP_CID_SIGNALING_LE,
                         L2CAP_CID_SECURITY_MANAGER_PROTOCOL,
                         L2CAP_CID_BR_EDR_SECURITY_MANAGER};

extern "C" void reset_bt_fuzz_state() { BTFuzzState::get()->reset(); }

BTFuzzState::BTFuzzState() { reset(); }

u32 BTFuzzState::serialize(u8 *buf) {
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

void BTFuzzState::deserialize(u8 *buf) {
  if (!buf) {
    reset();
    return;
  }

  // Deserialize Connection States
  item_t *pItem = (item_t *)buf;
  hci_con *pCon = (hci_con *)pItem->data;
  while ((u8 *)pCon - pItem->data < pItem->size) {
    sCon.insert(*pCon);
    pCon++;
  }

  // Deserialize Cids
  pItem = (item_t *)&pItem->data[pItem->size];
  u16 *pCid = (u16 *)pItem->data;
  while ((u8 *)pCid - pItem->data < pItem->size) {
    sCid.insert(*pCid);
    pCid++;
  }

  // Deserialize Psms
  pItem = (item_t *)&pItem->data[pItem->size];
  u16 *pPsm = (u16 *)pItem->data;
  while ((u8 *)pPsm - pItem->data < pItem->size) {
    sPsm.insert(*pPsm);
    pPsm++;
  }

  sync();
}

void BTFuzzState::reset() {
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

void BTFuzzState::sync() {
  if (Parameter *pCon = get_parameter(CORE_PARAMETER_HCI_HANDLE)) {
    pCon->domain.clear();
  }
  if (Parameter *pPsm = get_parameter(CORE_PARAMETER_PSM)) {
    pPsm->domain.clear();
    for (u16 psm : sPsm) pPsm->domain.insert(bytes2vec(psm));
  }
  if (Parameter *pCid = get_parameter(CORE_PARAMETER_CID)) {
    pCid->domain.clear();
    for (u16 cid : sCid) pCid->domain.insert(bytes2vec(cid));
  }
}

u32 BTFuzzState::step_one(u8 *items, u32 size) {
  item_t *pItem = (item_t *)items;
  item_t *pItemIn;
  item_t *pItemOut = (item_t *)hci;
  BT_ItemForEach3(pItem, items, size) { pItemIn = pItem; }

  // handle_item(pItemIn);
  switch (pItemIn->data[0]) {
    case OPERATION:
      handle_op((operation_t *)pItemIn->data);
      break;
    case HCI_EVENT_PACKET:
      handle_evt((hci_event_t *)pItemIn->data);
      break;
  }

  BT_ItemForEach2(pItemOut, hci) {
    switch (pItemOut->data[0]) {
      case HCI_COMMAND_DATA_PACKET:
        handle_cmd((hci_command_t *)pItemOut->data);
        break;
      case HCI_ACL_DATA_PACKET:
        break;
    }
  }
}

u32 BTFuzzState::fuzz_one(u8 *buf) {
  u32 r = rand_below(100);

  if (r <= 30 && sema) {
  } else {
  }

  if (r <= 100) {
    Operation *op = get_operation(rand_below(operations.size()));
    op->generate();
    return op->serialize(buf);
  }
}

void BTFuzzState::handle_cmd(hci_command_t *cmd) {
  vector<u8> _cmd;
  _cmd.insert(_cmd.end(), (u8 *)cmd, (u8 *)cmd + cmd->len + 3);
  sPending_cmd.insert(_cmd);

  // switch (cmd->opcode) {
  //   case BT_HCI_CMD_CREATE_CONN: {
  //     bt_hci_cmd_create_conn *c = (bt_hci_cmd_create_conn *)cmd->param;
  //     hci_con con;
  //     sPending_con.insert(*addr);
  //     break;
  //   }
  //   case BT_HCI_CMD_CREATE_CONN_CANCEL: {
  //     bt_hci_cmd_create_conn_cancel *c =
  //         (bt_hci_cmd_create_conn_cancel *)cmd->param;
  //     bd_addr *addr = (bd_addr *)c->bdaddr;
  //     break;
  //   }
  //   case BT_HCI_CMD_DISCONNECT: {
  //     bt_hci_cmd_disconnect *c = (bt_hci_cmd_disconnect *)cmd->param;
  //     break;
  //   }
  //   case BT_HCI_CMD_LE_CREATE_CONN: {
  //     bt_hci_cmd_le_create_conn *c = (bt_hci_cmd_le_create_conn *)cmd->param;
  //     break;
  //   }
  //   case BT_HCI_CMD_LE_CREATE_CONN_CANCEL: {
  //   }
  //   default:
  //     break;
  // }
}

void BTFuzzState::handle_evt(hci_event_t *evt) {
  switch (evt->opcode) {
    case BT_HCI_EVT_CMD_COMPLETE: {
      bt_hci_evt_cmd_complete *e = (bt_hci_evt_cmd_complete *)evt->param;
      for (auto it = sPending_cmd.begin(), eit = sPending_cmd.end(); it != eit;
           ++it) {
        hci_command_t *cmd = (hci_command_t *)it->data();
        if (cmd->opcode == e->opcode) {
          sPending_cmd.erase(it);
          break;
        }
      }
      break;
    }
    case BT_HCI_EVT_CMD_STATUS: {
      bt_hci_evt_cmd_status *e = (bt_hci_evt_cmd_status *)evt->param;
      for (auto it = sPending_cmd.begin(), eit = sPending_cmd.end(); it != eit;
           ++it) {
        hci_command_t *cmd = (hci_command_t *)it->data();
        if (e->opcode == cmd->opcode) {
          if (e->opcode == BT_HCI_CMD_CREATE_CONN &&
              e->status == BT_HCI_ERR_SUCCESS) {
            hci_con con;
            bt_hci_cmd_create_conn *c = (bt_hci_cmd_create_conn *)cmd->param;
            con.type = BD_ADDR_TYPE_ACL;
            memcpy(con.addr.addr, c->bdaddr, 6);
            sPending_con.insert(con);
          } else if (e->opcode == BT_HCI_CMD_DISCONNECT &&
                     e->status == BT_HCI_ERR_SUCCESS) {
            bt_hci_cmd_disconnect *c = (bt_hci_cmd_disconnect *)cmd->param;
            sPending_discon.insert(c->handle);
          }
          sPending_cmd.erase(it);
          break;
        }
      }
      break;
    }
    case BT_HCI_EVT_CONN_COMPLETE: {
      bt_hci_evt_conn_complete *e = (bt_hci_evt_conn_complete *)evt->param;
      if (e->status == BT_HCI_ERR_SUCCESS) {
        hci_con c;
        c.handle = e->handle;
        memcpy(c.addr.addr, e->bdaddr, 6);
        c.type = BD_ADDR_TYPE_ACL;
        sCon.insert(c);
      }
      break;
    }
    case BT_HCI_EVT_DISCONNECT_COMPLETE: {
      bt_hci_evt_disconnect_complete *e =
          (bt_hci_evt_disconnect_complete *)evt->param;
      if (e->status == BT_HCI_ERR_SUCCESS) {
        for (auto it = sCon.begin(), eit = sCon.end(); it != eit; ++it) {
          if (it->handle == e->handle) {
            sCon.erase(it);
            sPending_discon.erase(it->handle);
            break;
          }
        }
      }
      break;
    }
    case BT_HCI_EVT_LE_META_EVENT: {
      switch (evt->param[0]) {
        case BT_HCI_EVT_LE_CONN_COMPLETE: {
          bt_hci_evt_le_conn_complete *e =
              (bt_hci_evt_le_conn_complete *)&evt->param[1];
          if (e->status == BT_HCI_ERR_SUCCESS) {
            hci_con c;
            c.handle = e->handle;
            memcpy(c.addr.addr, e->peer_addr, 6);
            c.type = e->peer_addr_type;
            sCon.insert(c);
          }
          break;
        }
        default:
          break;
      }
      break;
    }

    default:
      break;
  }
}

void BTFuzzState::handle_op(operation_t *op) {
  Operation *pOp = get_operation(op->id);
  if (pOp->name == CORE_OPERATION_L2CAP_CREATE_CHANNEL)
    handle_op_l2cap_create_channel(op);
  else if (pOp->name == CORE_OPERATION_L2CAP_REGISTER_SERVICE)
    handle_op_l2cap_register_service(op);
}

void BTFuzzState::handle_evt_con_complete(hci_event_t *evt) {}

void BTFuzzState::handle_evt_le_con_complete(hci_event_t *evt) {}

void BTFuzzState::handle_op_l2cap_create_channel(operation_t *op) {
  u16 *cid = (u16 *)rt;
  vCid.push_back(*cid);
  sCid.insert(*cid);
}

void BTFuzzState::handle_op_l2cap_register_service(operation_t *op) {
  Parameter *psm = get_parameter(CORE_PARAMETER_PSM);
  get_operation(op->id)->deserialize(op);
  vPsm.push_back(*(u16 *)psm->data);
  sPsm.insert(*(u16 *)psm->data);
}
