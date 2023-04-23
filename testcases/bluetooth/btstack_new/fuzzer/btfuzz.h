#ifndef BTFUZZ_FUZZ_H
#define BTFUZZ_FUZZ_H

#include "btfuzz_type.h"

extern char* hci_sock_path;
extern int hci_sock_fd;

void hci_packet_handler(u8 *packet_in, u32 len);

typedef struct __attribute__((packed)) {
  u8 opcode;
  u8 len;
  u8 param[];
} hci_event_t;
#define HCI_EVENT_OPCODE(packet) (((hci_event_t*)packet)->opcode)
#define HCI_EVENT_PARAM(packet, evt)

typedef struct  __attribute__((packed)){
  u16 opcode;
  u8 len;
  u8 param[];
} hci_command_t ;
#define HCI_COMMAND_HEADER 
#define HCI_COMMAND_OPCODE(packet) (((hci_command_t*)packet)->opcode)
#define HCI_COMMAND_PARAM(packet, type, p) type* p = (type*)(((hci_command_t*)packet)->param)

typedef struct __attribute__((packed)){
  u16 handle;
  u16 len;
  u8 data[];
} hci_acl_t   ;
#define HCI_ACL_HANDLE(packet) (((hci_acl_t*)packet)->handle)

typedef struct __attribute__((packed)) {
  u16 len;
  u16 cid;
  u8 data[];
} l2cap_hdr ;
#define HCI_ACL_L2CAP_CID(packet) (((hci_ac*)packet)->handle)

#define ACL_Data_Packet_Length 1021
#define Synchronous_Data_Packet_Length 96
#define Total_Num_ACL_Data_Packets 4
#define Total_Num_Synchronous_Data_Packets 6

#define LE_ACL_Data_Packet_Length 0x1B
#define Total_Num_LE_ACL_Data_Packets 3
#define ISO_Data_Packet_Length 244
#define Total_Num_ISO_Data_Packets 8

#define Filter_Accept_List_Size 4


void hci_packet_handler(u8* buf, u32 len);

#define cast_define(type, to, from) type to = (type)from

#endif