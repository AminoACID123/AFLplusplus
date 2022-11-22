
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "../../../include/bluetooth.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;

extern u8* __afl_area2_ptr;
extern u32 log_ptr;
extern void (*fuzz_packet_handler)(u8 packet_type, u8 *packet, uint16_t size);

extern void* arg_in[];
extern void* arg_out[];
extern void* context[];

static u8* BUF;
static u32 SIZE;
static u32 POS;

typedef void (*fun_ptr)();
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

void execute_api(u8 *buf, u32 size) {

  u32 harness_idx = *(u32*)(buf + 1);

  *(u32*)(__afl_area2_ptr + log_ptr) = 1;
  log_ptr += 4;
  __afl_area2_ptr[log_ptr++] = OPERATION;


  u32 arg_in_count, arg_out_count;

  arg_in_count = *(u32*)(buf + 5);

  u32 pos = 9;

  for(u32 i=0;i<arg_in_count;i++){
    s32 arg_idx = *(s32*)(buf + pos);
    pos += 4;
    if (arg_idx >= 0) {
      u32 len = *(u32*)(buf + pos);
      arg_in[i*2+1] = (u32*)(buf + pos);
      pos += sizeof(u32);
      arg_in[i*2] = (u8*)(buf + pos);
      
      pos += len;
    } else {
      arg_in[i] = context[-arg_idx];
    }
  }
/*
  arg_out_count = *(int *)(buf + pos);
  pos += 4;

  for(int i=0;i<arg_out_count;i++){
      int idx = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_out[i] = context[idx];
  }
*/

  FUZZ_LIST[harness_idx]();
}

void execute_hci(u8* hci_packet_in, u32 size){
    u32 packet_len;
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
    *(u32*)(__afl_area2_ptr + log_ptr) = size;
    log_ptr += 4;
    memcpy(__afl_area2_ptr + log_ptr, hci_packet_in, size);
    log_ptr += size;

    fuzz_packet_handler(hci_packet_in[0], &hci_packet_in[1], packet_len-1);
}

bool execute_one(){
  if(POS >= SIZE)
    return false;

  u32 size = *(u32*)(BUF + POS);
  POS += 4;
  if(BUF[POS] == OPERATION)
    execute_api(BUF + POS, size);
  else 
    execute_hci(BUF + POS, size);
  POS += size;
  return true;
}

void stack_execute(u8* buf, u32 size){
  BUF = buf;
  SIZE = size;
  POS = 0;
  btstack_run_loop_execute();
}