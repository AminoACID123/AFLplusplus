#include <assert.h>
#include <aio.h>
#include <stdio.h>
#include <sys/uio.h>
#include <alloca.h>
#include <unistd.h>
#include <stdlib.h>

#include "common/bluetooth.h"
#include "common/random.h"
#include "common/transport.h"
#include "common/util.h"
#include "protocols/btfuzz_hci.h"
#include "protocols/btfuzz_att.h"
#include "btfuzz.h"

bool initial_setup = true;
char *hci_sock_path = "/tmp/hci.sock";
int hci_sock_fd;

extern int stack_initialized;

#define ATT_CHARACTERISTIC_0000FF11_0000_1000_8000_00805F9B34FB_01_CLIENT_CONFIGURATION_HANDLE 0x000e


void btfuzz_step_one()
{
  if ( 1 == stack_initialized)
  {
    bd_addr_t addr = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    bd_addr_type_t type = BD_ADDR_TYPE_LE_PUBLIC;
    create_le_connection(addr, type);
    stack_initialized = 2;
  }else if (stack_initialized == 2){
      // send_att_exchange_mtu_req(btfuzz->next_handle, 55);
      u16 val = 1;
      send_att_write_req(btfuzz->next_handle, 0x000e, &val, 2);
    stack_initialized = 3;
  }
}

void btfuzz_packet_handler(u8 *packet_in, u32 packet_len) {
  if (packet_len == 0)
    return;
    
  dump_packet("packet: ", packet_in[0], packet_in, packet_len);
  u32 pos, len;
  pos = len = 0;
  while (pos < packet_len)
  {
    switch (packet_in[pos]) {
      case HCI_COMMAND_DATA_PACKET:{
        cast_define(bt_hci_cmd_hdr*, c, packet_in + pos + 1);
        len = c->len + sizeof(bt_hci_cmd_hdr);
        hci_command_handler((u8*)c, len);
        pos += (1 + len);
        break;
      }
      case HCI_ACL_DATA_PACKET:{
        cast_define(bt_hci_acl_hdr*, acl, packet_in + pos + 1);
        len = acl->len + sizeof(bt_hci_acl_hdr);
        hci_acl_handler((u8*)acl, len);
        pos += (1 + len);
        break;
      }
      default:
        assert(false && "Unknown packet type");
    }
  }
  

}
