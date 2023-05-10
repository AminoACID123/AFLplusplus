#include "common/transport.h"
#include "common/util.h"
#include "btfuzz.h"
#include <stdio.h>
#include <sys/uio.h>

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
  
  struct iovec iov[2] = {{.iov_base = &type, .iov_len = 1},
                         {.iov_base = packet, .iov_len = len}};

  writev(hci_sock_fd, iov, 2);               
  dump_packet("sent", type, packet, len);
}
