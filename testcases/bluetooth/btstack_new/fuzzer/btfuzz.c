

#include <aio.h>
#include <stdio.h>
#include <sys/uio.h>
#include <alloca.h>
#include <unistd.h>
#include <stdlib.h>

#include "btfuzz_bluetooth.h"
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

    default:
      break;
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
