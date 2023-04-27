#ifndef BTFUZZ_FUZZ_H
#define BTFUZZ_FUZZ_H

#include "common/type.h"

extern char* hci_sock_path;
extern int hci_sock_fd;

void hci_packet_handler(u8 *packet_in, u32 len);

typedef struct __attribute__((packed)) {
  u8 opcode;
  u8 len;
  u8 param[];
} hci_event_t;

typedef struct  __attribute__((packed)){
  u16 opcode;
  u8 len;
  u8 param[];
} hci_command_t ;

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

#define ACL_Data_Packet_Length 1021
#define Synchronous_Data_Packet_Length 96
#define Total_Num_ACL_Data_Packets 4
#define Total_Num_Synchronous_Data_Packets 6

#define LE_ACL_Data_Packet_Length 0x1B
#define Total_Num_LE_ACL_Data_Packets 3
#define ISO_Data_Packet_Length 244
#define Total_Num_ISO_Data_Packets 8

#define Filter_Accept_List_Size 4

#define LINK_TYPE_ACL 1
#define LINK_TYPE_SCO 0

void hci_packet_handler(u8* buf, u32 len);



#endif