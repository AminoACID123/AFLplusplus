#include "btfuzz.h"
#include "btfuzz_state.h"
#include "protocols/btfuzz_hci.h"
#include "common/bluetooth.h"
#include "common/transport.h"

#include <assert.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>

int stack_initialized = 0;

void send_event(u8 opcode, void* data, u32 len)
{
  btfuzz_alloc_event(e, opcode, len)
  memcpy(e->param, data, len);
  send_packet(HCI_EVENT_PACKET, (u8*)e, e->len + sizeof(bt_hci_evt_hdr));
}

void send_command_complete_event(u16 opcode, u8 ncmd, void *data, u32 len) {
  btfuzz_alloc_event(e, BT_HCI_EVT_CMD_COMPLETE, sizeof(bt_hci_evt_cmd_complete) + len)
  cast_define(bt_hci_evt_cmd_complete*, cc, e->param);

  cc->ncmd = ncmd;
  cc->opcode = opcode;
  memcpy(cc->param, data, len);
  send_packet(HCI_EVENT_PACKET, (u8*)e, e->len + sizeof(bt_hci_evt_hdr));
}

void send_command_status_event(u16 opcode, u8 ncmd, u8 status) {
  btfuzz_alloc_event(e, BT_HCI_EVT_CMD_STATUS, sizeof(bt_hci_evt_cmd_status))
  cast_define(bt_hci_evt_cmd_status*, cs, e->param);

  cs->ncmd = ncmd;
  cs->opcode = opcode;
  cs->status = status;
  send_packet(HCI_EVENT_PACKET, (u8*)e, e->len + sizeof(bt_hci_evt_hdr));
}

void send_connection_request_event(bd_addr_t addr)
{
  btfuzz_alloc_event(e, BT_HCI_EVT_CONN_REQUEST, sizeof(bt_hci_evt_conn_request))
  cast_define(bt_hci_evt_conn_request*, cr, e->param);

  memcpy(cr->bdaddr, addr, 6);
  cr->link_type = LINK_TYPE_ACL;
  send_packet(HCI_EVENT_PACKET, (u8*)e, e->len + sizeof(bt_hci_evt_hdr));
}

void send_le_connection_complete_event(bd_addr_t addr, bd_addr_type_t type)
{
  btfuzz_alloc_le_event(e, BT_HCI_EVT_LE_CONN_COMPLETE, sizeof(bt_hci_evt_le_conn_complete))
  cast_define(bt_hci_evt_le_conn_complete*, lcc, &e->param[1]);

  lcc->status = BT_HCI_ERR_SUCCESS;
  bd_addr_t remote_addr = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
  memcpy(lcc->peer_addr, remote_addr, BD_ADDR_LEN);
  lcc->peer_addr_type = 0;
  lcc->handle = 1;
  send_packet(HCI_EVENT_PACKET, (u8*)e, e->len + sizeof(bt_hci_evt_hdr));
}

void create_le_connection(bd_addr_t addr, bd_addr_type_t type)
{
  send_le_connection_complete_event(addr, type);
  hci_connection_t* conn = malloc(sizeof(hci_connection_t));
  conn->handle = ++btfuzz->next_handle;
  btfuzz_vector_push_back(&btfuzz->connections, conn);
}

void hci_command_handler(u8 *packet, u32 len) {
  cast_define(bt_hci_cmd_hdr*, c, packet);
  switch (c->opcode) {
    case BT_HCI_CMD_RESET: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_VERSION: {
      bt_hci_rsp_read_local_version rsp = {.status = BT_HCI_ERR_SUCCESS,
                                                  .hci_ver = 0x0C,
                                                  .hci_rev = 0xFF,
                                                  .lmp_ver = 0x0C,
                                                  .manufacturer = 0xFF,
                                                  .lmp_subver = 0xFF};
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_NAME: {
      bt_hci_rsp_read_local_name rsp = {.status = BT_HCI_ERR_SUCCESS,
                                               .name = "BTFuzz"};
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_COMMANDS: {
      bt_hci_rsp_read_local_commands rsp;
      memset(&rsp, 0xFF, sizeof(rsp));
      rsp.status = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_BD_ADDR: {
      bt_hci_rsp_read_bd_addr rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .bdaddr = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
      };
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_BUFFER_SIZE : {
      bt_hci_rsp_read_buffer_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .acl_mtu = ACL_Data_Packet_Length,
        .sco_mtu = Synchronous_Data_Packet_Length,
        .acl_max_pkt = Total_Num_ACL_Data_Packets,
        .sco_max_pkt = Total_Num_Synchronous_Data_Packets
      };
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_FEATURES: {
      bt_hci_rsp_read_local_features rsp;
      memset(&rsp, 0xFF, sizeof(rsp));
      rsp.status = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_SET_EVENT_MASK: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_SET_EVENT_MASK_PAGE2: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_LE_READ_BUFFER_SIZE_V2: {
      bt_hci_rsp_le_read_buffer_size_v2 rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .acl_mtu = LE_ACL_Data_Packet_Length,
        .acl_max_pkt = Total_Num_LE_ACL_Data_Packets,
        .iso_mtu = ISO_Data_Packet_Length,
        .iso_max_pkt = Total_Num_ISO_Data_Packets
      }; 
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_LE_SET_EVENT_MASK: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH: {
      bt_hci_rsp_le_read_max_data_length rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .max_tx_len = 0xFB,
        .max_tx_time = 0x4290,
        .max_rx_len = 0xFB,
        .max_rx_time = 0x4290
      };
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_LE_WRITE_DEFAULT_DATA_LENGTH: {
      cast_define(bt_hci_cmd_le_write_default_data_length*, cmd, c->param);
      printf("Host suggest data length %d\n", cmd->tx_len);
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break; 
    }
    case BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE: {
      bt_hci_rsp_le_read_accept_list_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .size = Filter_Accept_List_Size
      };
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break; 
    }
    case BT_HCI_CMD_LE_SET_SCAN_PARAMETERS: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break; 
    }
    case BT_HCI_CMD_LE_RAND:{
      bt_hci_rsp_le_rand rsp;
      rsp.status = BT_HCI_ERR_SUCCESS;
      //rand_fill(rsp.number, 8);
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break; 
    }
    case BT_HCI_CMD_LE_SET_ADV_PARAMETERS: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;       
    }
    case BT_HCI_CMD_LE_SET_ADV_DATA: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      cast_define(bt_hci_cmd_le_set_adv_data*, cmd, c->param);
      printf("Adv Data: %s\n", cmd->data);
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;   
    }
    case BT_HCI_CMD_LE_SET_ADV_ENABLE: {
      cast_define(bt_hci_cmd_le_set_adv_enable*, cmd, c->param);
      printf("ADV enabled: %d\n", cmd->enable);
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      stack_initialized = 1;
      break;
    }
    case BT_HCI_CMD_LE_SET_RESOLV_ENABLE: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE: {
      bt_hci_rsp_le_read_resolv_list_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .size = 0
      };
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break; 
    }
    case BT_HCI_CMD_LE_CLEAR_RESOLV_LIST : {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;  
    }
    case BT_HCI_CMD_LE_READ_REMOTE_FEATURES: {
      cast_define(bt_hci_cmd_le_read_remote_features*, cmd, c->param);
      bt_hci_evt_remote_features_complete rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .handle = cmd->handle,
      };
      memset(&rsp.features, 0xff, sizeof(rsp.features));
      send_event(BT_HCI_EVT_REMOTE_FEATURES_COMPLETE, &rsp, sizeof(rsp));
      break;
    }

    default:{
      u8 rsp = BT_HCI_ERR_SUCCESS;
      assert(false);
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;     
    }
  }
}

void hci_acl_handler(u8 *packet, u32 len) {}