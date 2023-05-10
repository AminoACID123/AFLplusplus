#ifndef BTFUZZ_FUZZ_H
#define BTFUZZ_FUZZ_H

#include "common/type.h"
#include "btfuzz_state.h"

extern char* hci_sock_path;
extern int hci_sock_fd;

void btfuzz_step_one();

void btfuzz_packet_handler(u8 *packet_in, u32 len);


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


#endif