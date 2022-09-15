
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "btstack_run_loop.h"
#include "hci_cmd.h"
#include "hci_transport.h"

extern char* __afl_area2_ptr;
extern int log_ptr;
//void (*fuzz_packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size);


static char* BUF;
static int SIZE;
static int POS;

#define API                     0xFF
#define HCI_COMMAND_DATA_PACKET 0x01
#define HCI_ACL_DATA_PACKET     0x02
#define HCI_SCO_DATA_PACKET     0x03
#define HCI_EVENT_PACKET        0x04
#define HCI_ISO_DATA_PACKET     0x05

extern char arg_in[];
extern char arg_out[];
extern char context[];

typedef void (*fun_ptr)(char **, char **);
extern fun_ptr FUZZ_LIST[];

/*
field                   bytes
----------------------------------
harness_idx             4
arg_in_count            4
arg1_idx                4
arg1_len                4
arg1_data               --
arg_out_count           4
arg1_idx                4

*/

void execute_api(char *buf, int size) {

  int harness_idx = *(int*)(buf + 1);

  *(int*)(__afl_area2_ptr + log_ptr) = 1;
  log_ptr += 4;
  __afl_area2_ptr[log_ptr++] = API;

  int arg_in_count, arg_out_count;

  arg_in_count = *(int*)(buf + 4);

  int pos = buf + 8;

  for(int i=0;i<arg_in_count;i++){
    int arg_idx = *(int*)(buf + pos);
    pos += 4;
    if (arg_idx == -1) {
      int len = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_in[i] = buf + pos;
      pos += len;
    } else {
      arg_in[i] = context[arg_idx];
    }
  }

  arg_out_count = *(int *)(buf + pos);
  pos += 4;

  for(int i=0;i<arg_out_count;i++){
      int idx = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_out[i] = context[idx];
  }
  
  FUZZ_LIST[harness_idx](arg_in, arg_out);
}

void execute_hci(char* hci_packet_in, int size){
    int packet_len;
    switch(hci_packet_in[0]){
        case HCI_EVENT_PACKET:
            packet_len = hci_packet_in[2] + 3;
            break;
        case HCI_ACL_DATA_PACKET:
            packet_len = little_endian_read_16(hci_packet_in, 3) + 5;
            break;
        default:
            return;
    }
    *(int*)(__afl_area2_ptr + log_ptr) = size;
    log_ptr += 4;
    memcpy(__afl_area2_ptr + log_ptr, hci_packet_in, size);
    log_ptr += 4;
    fuzz_packet_handler(hci_packet_in[0], &hci_packet_in[1], packet_len-1);
}

bool execute_one(){
    if(POS >= SIZE)
        return false;

    int size = *(int*)(BUF + POS);
    POS += 4;
    if(BUF[POS] == API)
        execute_api(BUF + POS, size);
    else
        execute_hci(BUF + POS, size); 
    POS += size;
    return true;
}

void stack_init(){
    
    btstack_memory_init();

    btstack_run_loop_init(btstack_run_loop_fuzz_get_instance());

    hci_init(hci_transport_fuzz_instance(), NULL);

    l2cap_init();

    gatt_client_init();

    sm_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);
}

void stack_execute(char* buf, int size){
    BUF = buf;
    SIZE = size;
    POS = 0;
    btstack_run_loop_execute();
}
