#ifndef _HAVE_BLUETOOTH_H
#define _HAVE_BLUETOOTH_H
#include "types.h"

/* Bluetooth related Macros */
#define OPERATION 0x06
#define HCI_COMMAND_DATA_PACKET 0x01
#define HCI_ACL_DATA_PACKET 0x02
#define HCI_SCO_DATA_PACKET 0x03
#define HCI_EVENT_PACKET 0x04
#define HCI_ISO_DATA_PACKET 0x05

#define BT_MAX_HCI_EVT_SIZE 255
#define BT_MAX_PARAM_SIZE 128
#define BT_MAX_BUFFER_SIZE 1024*1024
#define BT_MAX_ITEM_COUNT 64

#define BT_MAX_SHM_SIZE 1024*1024

/**
 * @format 12R
 * @param num_hci_command_packets
 * @param command_opcode
 * @param return_parameters
 */
#define HCI_EVENT_COMMAND_COMPLETE 0x0Eu
/**
 * @format 112
 * @param status
 * @param num_hci_command_packets
 * @param command_opcode
 */
#define HCI_EVENT_COMMAND_STATUS 0x0Fu

typedef struct __attribute__((packed)){
    u32 size;
    u8 data[0];
} item_t ;

typedef struct __attribute__((packed)){
    u8 flag;
    u32 id;
    u32 params;
    u8 data[0];
} operation_t;

typedef struct  __attribute__((packed)) {
    u32 len;
    u8  data[0];
} parameter_t;

typedef struct __attribute__((packed)) {
  u8 flag;
  u8 opcode;
  u8 len;
  u8 param[0];
} hci_event_t;

typedef struct __attribute__((packed)) {
  u8 flag;
  u16 opcode;
  u8 len;
  u8 param[0];
} hci_command_t;

typedef struct __attribute__((packed)) {
  u8 flag;
  u16 handle;
  u16 len;
  u8 data[0];
} hci_acl_t;

typedef struct __attribute__((packed)) {
  u8  pkts;
  u16 opcode;
  u8  param[0];
} hci_event_command_complete;

typedef struct __attribute__((packed)) {
  u8  status;
  u8  pkts;
  u16 opcode;
} hci_event_command_status ;


#define BT_ItemForEach(item, array, size) for(item=(item_t*)array;(u8*)item-(u8*)array<size;item=(item_t*)&item->data[item->size])

static inline u32 bt_item_nr(u8* buf, u32 size){
  u32 n = 0;
  item_t* pItem;
  BT_ItemForEach(pItem, buf, size){n++;}
  return n;
}

static inline item_t* bt_item_at(u8* buf, u32 size, u32 i){
  item_t* pItem;
  BT_ItemForEach(pItem, buf, size){
    if(i-- == 0)
      return pItem;
  }
  return NULL;
}


#endif
