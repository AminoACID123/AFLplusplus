#include "BTFuzz.h"
#include "../../include/afl-fuzz.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "BTFuzzState.h"
#include "Hci.h"
#include "Item.h"
#include "Operation.h"
#include "Serialize.h"
#include <assert.h>
#include <iostream>
#include <map>
#include <set>
#include <string.h>
#include <vector>

using namespace std;

BTFuzz *BTFuzz::bt = nullptr;

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

vector<u8> core_events = {BT_HCI_EVT_CONN_COMPLETE, BT_HCI_EVT_CONN_REQUEST,
                          BT_HCI_EVT_DISCONNECT_COMPLETE};

vector<u16> core_commands = {
    BT_HCI_CMD_CREATE_CONN, BT_HCI_CMD_CREATE_CONN_CANCEL,
    BT_HCI_CMD_DISCONNECT, BT_HCI_CMD_ACCEPT_CONN_REQUEST};

u8 bd_addrs[][6] = {{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
                    {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
                    {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc},
                    {0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd},
                    {0xee, 0xee, 0xee, 0xee, 0xee, 0xee}};

extern "C" const char* bt_get_op_str() { return BTFuzz::get()->get_op(); }

extern "C" void bt_enable_sema(bool sema) { BTFuzz::get()->enable_sema(sema); }

extern "C" bool bt_sema_enabled() { return BTFuzz::get()->sema_enabled(); }

extern "C" void bt_set_buf(u8 *hci, u8 *rt) {
  BTFuzz::get()->set_buffers(hci, rt);
}

extern "C" void bt_rand_init(u32 fd) { rand_init(fd); }

extern "C" void bt_restore_state() { BTFuzz::get()->restore_state(); }

extern "C" void bt_sync_hci() { BTFuzz::get()->sync_hci(); }

extern "C" u32 bt_serialize_state(u8 *buf) {
  return BTFuzz::get()->serialize_state(buf);
}

extern "C" void bt_deserialize_state(u8 *buf) {
  BTFuzz::get()->deserialize_state(buf);
}

extern "C" void bt_fuzz_one(u8 *buf) { BTFuzz::get()->fuzz_one(buf); }

u32 BTFuzz::serialize_state(u8 *buf) {
  BinarySerialize s(buf);
  s << cur_state;
  return s.len();
}

void BTFuzz::deserialize_state(u8 *buf) {
  if (buf) {
    BinaryDeserialize s(buf);
    s >> init_state;
    cur_state = init_state;
  } else {
    init_state.reset();
    cur_state = init_state;
  }

  // sync_state();
}

void BTFuzz::restore_state() {
  cur_state = init_state;
  // sync_state();
}

// void BTFuzz::sync_state() {
//   Parameter *_handle = get_parameter(CORE_PARAMETER_HCI_HANDLE);
//   Parameter *_cid = get_parameter(CORE_PARAMETER_CID);
//   Parameter *_psm = get_parameter(CORE_PARAMETER_PSM);

//   _handle->domain.resize(cur_state.con.size());
//   for (u32 i = 0, n = cur_state.con.size(); i < n; ++i)
//     bytes2vec(_handle->domain[i], cur_state.con[i]);

//   _cid->domain.resize(cur_state.cid.size());
//   for (u32 i = 0, n = cur_state.cid.size(); i < n; ++i)
//     bytes2vec(_cid->domain[i], cur_state.cid[i]);

//   _psm->domain.resize(cur_state.psm.size());
//   for (u32 i = 0, n = cur_state.psm.size(); i < n; ++i)
//     bytes2vec(_psm->domain[i], cur_state.psm[i]);
// }

u32 BTFuzz::fuzz_one(u8 *buf) {
  if (sema)
    return fuzz_one_sema(buf);
  else
    return fuzz_one_rand(buf);
}

u32 BTFuzz::handle_cmd(u8* buf, hci_command_t* cmd)
{
  char str[100];
  u32 s = rand_below(100);
  s = (s >= 90 ? s % 10 : BT_HCI_ERR_SUCCESS);
  u32 n = rand_below(10);
  sprintf(str, "sema1-cmd0x%04xs%dn%d", cmd->opcode, s, n);
  opStr = str;

  CmdStatusEvent evt1(buf, s, n, cmd->opcode);

  if (cmd->opcode == BT_HCI_CMD_CREATE_CONN) {
    bt_hci_cmd_create_conn *c = (bt_hci_cmd_create_conn *)cmd->param;
    if (s == BT_HCI_ERR_SUCCESS) {
      cur_state.add_pending_con(BD_ADDR_TYPE_ACL, c->bdaddr);
    }
    return evt1.size() + sizeof(u32);
  } else if (cmd->opcode == BT_HCI_CMD_DISCONNECT) {
    bt_hci_cmd_disconnect *c = (bt_hci_cmd_disconnect *)cmd->param;
    if (s == BT_HCI_ERR_SUCCESS && cur_state.has_connection(c->handle)) {
      cur_state.add_pending_discon(c->handle);
    }
    return evt1.size() + sizeof(u32);
  } else if (cmd->opcode == BT_HCI_CMD_ACCEPT_CONN_REQUEST) {
    bt_hci_cmd_accept_conn_request *c =
        (bt_hci_cmd_accept_conn_request *)cmd->param;
    if (s == BT_HCI_ERR_SUCCESS) {
      cur_state.add_pending_con(BD_ADDR_TYPE_ACL, c->bdaddr);
    }
    return evt1.size() + sizeof(u32);
  } else if (cmd->opcode == BT_HCI_CMD_LE_CREATE_CONN) {
    bt_hci_cmd_le_create_conn *c = (bt_hci_cmd_le_create_conn *)cmd->param;
    if (s == BT_HCI_ERR_SUCCESS) {
      cur_state.add_pending_con(c->peer_addr_type, c->peer_addr);
    }
    return evt1.size() + sizeof(u32);
  }else if (cmd->opcode == BT_HCI_CMD_LE_EXT_CREATE_CONN) {
    bt_hci_cmd_le_ext_create_conn *c = (bt_hci_cmd_le_ext_create_conn *)cmd->param;
    if (s == BT_HCI_ERR_SUCCESS) {
      cur_state.add_pending_con(c->peer_addr_type, c->peer_addr);
    }
    return evt1.size() + sizeof(u32);
  } else if (sStatusCmd.find(cmd->opcode) != sStatusCmd.end()) {
    return evt1.size() + sizeof(u32);
  }

  // bt_hci_evt_cmd_complete *pCplt = (bt_hci_evt_cmd_complete *)pEvt->param;
  // pCplt->ncmd = s % 10;
  // pCplt->opcode = cmd->opcode;
  // pEvt->len = sizeof(bt_hci_evt_cmd_complete);
  // pItem->size = sizeof(hci_event_t) + pEvt->len;

  CmdCompleteEvent evt2(buf, n, cmd->opcode);

  if (cmd->opcode == BT_HCI_CMD_CREATE_CONN_CANCEL) {
    bt_hci_cmd_create_conn_cancel *c =
        (bt_hci_cmd_create_conn_cancel *)cmd->param;
    *(u8 *)evt2.data()->param = s;
    memcpy(&evt2.data()->param[1], c->bdaddr, 6);
    cur_state.remove_pending_con(c->bdaddr);
  } else if (cmd->opcode == BT_HCI_CMD_LE_CREATE_CONN_CANCEL) {
    *(u8 *)evt2.data()->param = s;
    cur_state.remove_pending_le_con();
  }
  return evt2.size() + sizeof(u32);
}

u32 BTFuzz::handle_acl(u8* buf, hci_acl_t* acl)
{
  bt_l2cap_hdr* l2cap = (bt_l2cap_hdr*)acl->data;
  if(l2cap->cid == L2CAP_CID_ATTRIBUTE_PROTOCOL)
    return handle_att(buf, (bt_l2cap_hdr_att*)l2cap->data);
  return 0;
}

u32 BTFuzz::handle_att(u8* buf, hci_acl_t* acl){
  if(rand_below(10) < 2)
  {
    ATTErrorResponse(buf, att->)
  }




  switch (att->code)
  {
  case /* constant-expression */:
    /* code */
    break;
  
  default:
    break;
  }
}

// reply pending hci packets
u32 BTFuzz::fuzz_one_sema1(u8 *buf) {
  if (cur_state.phci.empty())
    return 0;

  u32 res = 0;
  u32 r = rand_below(cur_state.phci.size());
  if(cur_state.phci[r][0] == HCI_COMMAND_DATA_PACKET){
    res = handle_cmd(buf, (hci_command_t*)cur_state.phci[r].data());
  }else if(cur_state.phci[r][0] == HCI_ACL_DATA_PACKET){
    res = handle_acl(buf, (hci_acl_t*)cur_state.phci[r].data());
  }
  cur_state.remove_phci(r);
  return res;
}

// core operations
u32 BTFuzz::fuzz_one_sema2(u8 *buf) {
  u32 r ;
  if(cur_state.con.empty()){
    r = rand_below(4) + 1;
  }else
    r = rand_below(5);
  
  Operation *op = NULL;
  char str[100];
  sprintf(str, "sema2-r%d", r);
  opStr = str;

  if (r == 0){
    op = get_operation(CORE_OPERATION_GAP_DISCONNECT)->arrange_bytes(buf);
    Parameter* param = get_parameter(CORE_PARAMETER_HCI_HANDLE);
    if(!cur_state.choose_con_handle((u16*)param->data, op->get_type())) return 0;
  }
  else if (r == 1){
    op = get_operation(CORE_OPERATION_GAP_CONNECT)->arrange_bytes(buf);
    for(Parameter* param : op->Inputs()){
      if(param->bytes == 6){
        memcpy(param->data, bd_addrs[rand_below(sizeof(bd_addrs) / 6)], 6);
      }else{
        param->data[0] = rand_below(param->enum_domain.size());
      }
    }
  }
  else if (r == 2)
    op = get_operation(CORE_OPERATION_GAP_CONNECT_CANCEL)->arrange_bytes(buf);
  else if (r == 3){
    op = get_operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL)->arrange_bytes(buf);
    for(Parameter* param : op->Inputs()){
      if(param->name == CORE_PARAMETER_BD_ADDR){
        memcpy(param->data, bd_addrs[rand_below(sizeof(bd_addrs) / 6)], 6);
      }else{
        assert(param->bytes == 2);
        *(u16*)param->data = rand_below(UINT16_MAX);
      }
    }    
  }
  else if (r == 4){
    op = get_operation(CORE_OPERATION_L2CAP_REGISTER_SERVICE)->arrange_bytes(buf);
    for(Parameter* param : op->Inputs()){
      if(param->name == CORE_PARAMETER_PSM){
        *(u16*)param->data = rand_below(UINT16_MAX);
        cur_state.add_psm(*(u16*)param->data);
      }else{
        assert(param->isEnum);
        param->data[0] = rand_below(param->enum_domain.size());
      }
    }
  }
  return op->size() + sizeof(u32);

}

// random operations
u32 BTFuzz::fuzz_one_sema3(u8 *buf) {
  Operation *op;
  op = &operations[rand_below(operations.size())];
  op->arrange_bytes(buf);
  opStr = "sema3";
  for (Parameter *param : op->Inputs()) {
    if (param->name == CORE_PARAMETER_HCI_HANDLE) {
      if(!cur_state.choose_con_handle((u16 *)param->data, op->get_type())) return 0;
    } else if (param->name == CORE_PARAMETER_CID) {
      if(!cur_state.choose_cid((u16 *)param->data)) return 0;
    } else if (param->name == CORE_PARAMETER_PSM) {
      if(!cur_state.choose_psm((u16 *)param->data)) return 0;
    }else if(param->name == CORE_PARAMETER_BD_ADDR){
      memcpy(param->data, bd_addrs[rand_below(sizeof(bd_addrs) / 6)], 6);
    } else {
      param->generate();
    }
  }

  return op->size() + sizeof(u32);
}

// random events
u32 BTFuzz::fuzz_one_sema4(u8 *buf) {
  u8 opcode = vEvt[rand_below(vEvt.size())];
  Event evt(buf, opcode);
  char str[100];
  sprintf(str, "sema4-opc%x", opcode);
  opStr = str;
  if (opcode == BT_HCI_EVT_LE_META_EVENT) {
    evt.data()->param[0] = vLeEvt[rand_below(vLeEvt.size())];
    rand_fill(&evt.data()->param[1], 255 -1);
  }else
    rand_fill(evt.data()->param, 255);
  return evt.size() + sizeof(u32);
}

// Core Events
u32 BTFuzz::fuzz_one_sema5(u8 *buf) {
  u32 r = rand_below(3);
  u32 s = rand_below(100);
  u32 n = rand_below(10);
  u32 size = 0;
  s = (s >= 90 ? s % 10 : BT_HCI_ERR_SUCCESS);
  char str[100];
  sprintf(str, "sema5-r%ds%dn%d", r, s, n);
  opStr = str;

  if (r == 0 && !cur_state.pcon.empty()) {
    u32 i = rand_below(cur_state.pcon.size());
    if (!BTFuzzState::is_le(cur_state.pcon[i].type)) {
      ConnCompleteEvent evt(buf);
      evt.data()->status = s;
      evt.data()->link_type = rand_below(2);
      evt.data()->encr_mode = rand_below(2);
      memcpy(evt.data()->bdaddr, cur_state.pcon[i].addr, 6);
      if (s == BT_HCI_ERR_SUCCESS) {
        cur_state.pcon[i].handle = evt.data()->handle = ++cur_state.max_handle;
        cur_state.add_con(cur_state.pcon[i]);
      }
      size = evt.size() + sizeof(u32);
    } else {
      LeConnCompleteEvent evt(buf);
      evt.data()->peer_addr_type = cur_state.pcon[i].type;
      evt.data()->role = rand_below(2);
      evt.data()->status = s;
      memcpy(evt.data()->peer_addr, cur_state.pcon[i].addr, 6);
      if (evt.data()->status == BT_HCI_ERR_SUCCESS) {
        cur_state.pcon[i].handle = evt.data()->handle = ++cur_state.max_handle;
        cur_state.add_con(cur_state.pcon[i]);
      }
      size = evt.size() + sizeof(u32);
    }
    cur_state.pcon.erase(cur_state.pcon.begin() + i);
  } else if (r == 1 && !cur_state.pdiscon.empty()) {
    u32 i = rand_below(cur_state.pdiscon.size());
    auto c = cur_state.get_connection(cur_state.pdiscon[i]);
    DisconnCompleteEvent evt(buf);
    evt.data()->handle = c.handle;
    evt.data()->status = s;
    evt.data()->reason = rand_below(UINT8_MAX);
    if (s == BT_HCI_ERR_SUCCESS) {
      cur_state.remove_con(c.handle);
    }
    cur_state.pdiscon.erase(cur_state.pdiscon.begin() + i);
    size = evt.size() + sizeof(u32);
  } else if (r == 2) {
    ConnRequestEvent evt(buf);
    rand_fill(evt.data()->dev_class, 3);
    evt.data()->link_type = rand_below(2);
    memcpy(evt.data()->bdaddr, bd_addrs[rand_below(sizeof(bd_addrs) / 6)],
           6);
    size = evt.size() + sizeof(u32);
  }
  return size;
}

void BTFuzz::sync_hci(){
  item_t* pItem;
  BT_ItemForEach2(pItem, hci){
    cur_state.add_phci(pItem);
  }
}

u32 BTFuzz::fuzz_one_sema(u8 *buf) {
  u32 r = rand_below(100);
  u32 res = 0;

  // Reply Pending Commands
  if (r < 50) {
    res = fuzz_one_sema1(buf);
    if (res)
      return res;
  }
  do {
    // Core Operations
    if (r < 10)
      res = fuzz_one_sema2(buf);
    // Random Operations
    else if (r < 50)
      res = fuzz_one_sema3(buf);
    // Random Events
    else if (r < 90)
      res = fuzz_one_sema4(buf);
    // Core Events
    else
      res = fuzz_one_sema5(buf);
  } while (res == 0);
  return res;
}

u32 BTFuzz::fuzz_one_rand(u8 *buf) {
  u32 size = 0;
  u32 rand = rand_below(6);
  char str[100];
  sprintf(str, "rand-r%d", rand);
  if (rand < 6) {
    Operation *op = get_operation(rand_below(operations.size()));
    op->arrange_bytes(buf);
    for (Parameter *param : op->Inputs()) {
      param->generate();
    }
    size = op->size() + sizeof(u32);
  } else if (rand < 4) {
    size = fuzz_one_sema4(buf);
  }
  return size;
}
