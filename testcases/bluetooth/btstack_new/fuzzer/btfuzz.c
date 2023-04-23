

#include <aio.h>
#include <stdio.h>
#include <sys/uio.h>
#include <alloca.h>
#include <unistd.h>
#include <stdlib.h>

#include "btfuzz_bluetooth.h"
#include "btfuzz_rand.h"
#include "btfuzz_util.h"
#include "btfuzz.h"

bool initial_setup = true;
char *hci_sock_path = "/tmp/hci.sock";
int hci_sock_fd;



void dump_packet(char *msg, u8 type, void *packet, u32 len) {
  if (type == HCI_COMMAND_DATA_PACKET)
    printf("Command %s: ", msg);
  else if (type == HCI_ACL_DATA_PACKET)
    printf("ACL %s: ", msg);
  else if (type == HCI_EVENT_PACKET)
    printf("Event %s: ", msg);
  printf_hexdump(packet, len);
}

void send_packet(u8 type, void *packet, u32 len) {
  dump_packet("sent", type, packet, len);
  struct iovec iov[2] = {{.iov_base = &type, .iov_len = 1},
                         {.iov_base = packet, .iov_len = len}};
  printf("%02x %ld\n",type, writev(hci_sock_fd, iov, 2));
}


void send_command_complete_event(u16 opcode, u8 ncmd, void *data, u32 len) {
  u32 packet_size =
      sizeof(hci_event_t) + sizeof(struct bt_hci_evt_cmd_complete) + len;
  u8 *packet = alloca(packet_size);
  hci_event_t *e = (hci_event_t *)packet;
  struct bt_hci_evt_cmd_complete *cc =
      (struct bt_hci_evt_cmd_complete *)e->param;

  e->opcode = BT_HCI_EVT_CMD_COMPLETE;
  e->len = sizeof(struct bt_hci_evt_cmd_complete) + len;
  cc->ncmd = ncmd;
  cc->opcode = opcode;
  memcpy(cc->param, data, len);
  send_packet(HCI_EVENT_PACKET, packet, e->len + sizeof(hci_event_t));
}

void send_command_status_event(u16 opcode, u8 ncmd, u8 status) {
  u32 packet_size = sizeof(hci_event_t) + sizeof(struct bt_hci_evt_cmd_status);
  u8 *packet = alloca(packet_size);
  hci_event_t *e = (hci_event_t *)packet;
  struct bt_hci_evt_cmd_status *cs = (struct bt_hci_evt_cmd_status *)e->param;

  e->opcode = BT_HCI_EVT_CMD_STATUS;
  e->len = sizeof(struct bt_hci_evt_cmd_status);
  cs->ncmd = ncmd;
  cs->opcode = opcode;
  cs->status = status;
  send_packet(HCI_EVENT_PACKET, packet, e->len + sizeof(hci_event_t));
}



void hci_command_handler(u8 *packet, u32 len) {
  hci_command_t *c = (hci_command_t *)packet;
  switch (c->opcode) {
    case BT_HCI_CMD_RESET: {
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_VERSION: {
      struct bt_hci_rsp_read_local_version rsp = {.status = BT_HCI_ERR_SUCCESS,
                                                  .hci_ver = 0x0C,
                                                  .hci_rev = 0xFF,
                                                  .lmp_ver = 0x0C,
                                                  .manufacturer = 0xFF,
                                                  .lmp_subver = 0xFF};
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_NAME: {
      struct bt_hci_rsp_read_local_name rsp = {.status = BT_HCI_ERR_SUCCESS,
                                               .name = "BTFuzz"};
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_LOCAL_COMMANDS: {
      struct bt_hci_rsp_read_local_commands rsp;
      memset(&rsp, 0xFF, sizeof(rsp));
      rsp.status = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_BD_ADDR: {
      struct bt_hci_rsp_read_bd_addr rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .bdaddr = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
      };
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;
    }
    case BT_HCI_CMD_READ_BUFFER_SIZE : {
      struct bt_hci_rsp_read_buffer_size rsp = {
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
      struct bt_hci_rsp_read_local_features rsp;
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
      struct bt_hci_rsp_le_read_buffer_size_v2 rsp = {
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
      struct bt_hci_rsp_le_read_max_data_length rsp = {
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
      cast_define(struct bt_hci_cmd_le_write_default_data_length*, cmd, c->param);
      printf("Host suggest data length %d\n", cmd->tx_len);
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break; 
    }
    case BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE: {
      struct bt_hci_rsp_le_read_accept_list_size rsp = {
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
      struct bt_hci_rsp_le_rand rsp;
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
      cast_define(struct bt_hci_cmd_le_set_adv_data*, cmd, c->param);
      printf("Adv Data: %s\n", cmd->data);
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;   
    }

    default:{
      u8 rsp = BT_HCI_ERR_SUCCESS;
      send_command_complete_event(c->opcode, 1, &rsp, sizeof(rsp));
      break;     
    }
  }
}

void hci_acl_handler(u8 *packet, u32 len) {}

void hci_packet_handler(u8 *packet_in, u32 len) {
  dump_packet("received", packet_in[0], &packet_in[1], len - 1);
  switch (packet_in[0]) {
    case HCI_COMMAND_DATA_PACKET:
      hci_command_handler(&packet_in[1], len - 1);
      break;
    case HCI_ACL_DATA_PACKET:
      hci_acl_handler(&packet_in[1], len - 1);
      break;
    default:
      break;
  }
}
