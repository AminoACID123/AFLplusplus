
#include <stdbool.h>
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
#include "../../../include/types.h"

extern u8* __afl_area2_ptr;
extern u32 log_ptr;
extern void* arg_in[];

item_t* pItem;
item_t* pItem_end;
item_t* pHCIItem;

typedef void (*fun_ptr)();
extern fun_ptr FUZZ_LIST[];


void execute_api(operation_t *op) {
  u32 id = op->id;
  parameter_t* pParam = (parameter_t*)op->data;

  for(u32 i=0;i<op->params;i++){
    arg_in[i * 2] = pParam->data;
    arg_in[i * 2 + 1] = &pParam->len;
    pParam = (parameter_t*)&pParam->data[pParam->len];
  }

  FUZZ_LIST[id]();
}

void execute_hci(u8* hci_packet_in){
  u32 packet_len;
  switch(hci_packet_in[0]){
      case HCI_EVENT_PACKET:{
          hci_event_t* evt = (hci_event_t*)hci_packet_in;
          packet_len = evt->len + sizeof(hci_event_t);
          break;
      }
      case HCI_ACL_DATA_PACKET:{
          hci_acl_t* acl = (hci_acl_t*)hci_packet_in;
          packet_len = acl->len + sizeof(hci_acl_t);
          break;
      }
      default:
          return;
  }
}

void execute_one(){
  pHCIItem = (item_t*)__afl_area2_ptr;
  pHCIItem->size = 0;

  if(pItem->data[0] == OPERATION)
    execute_api(pItem->data);
  else 
    execute_hci(pItem->data);
  pItem = (item_t*)&pItem->data[pItem->size];
  pHCIItem->size = 0;
}

void stack_execute(u8* buf, u32 size){
  pItem = (item_t*)buf;
  pItem_end = (item_t*)(buf + size);
  pHCIItem = (item_t*)__afl_area2_ptr;

  while (pItem < pItem_end)
  {
    execute_one();  
  }
  
}