#ifndef BLUETOOTH_H
#define BLUETOOTH_H
#include "types.h"
/* Bluetooth related Macros */
#define F_API                   0x06
#define HCI_COMMAND_DATA_PACKET 0x01
#define HCI_ACL_DATA_PACKET     0x02
#define HCI_SCO_DATA_PACKET     0x03
#define HCI_EVENT_PACKET        0x04
#define HCI_ISO_DATA_PACKET     0x05

#define BT_MAX_HCI_EVT_SIZE     255
#define BT_MAX_PARAM_SIZE       128
#define BT_MAX_BUFFER_SIZE      BT_MAX_PARAM_SIZE * 16

/**
 * @format 12R
 * @param num_hci_command_packets
 * @param command_opcode
 * @param return_parameters
 */
#define HCI_EVENT_COMMAND_COMPLETE                         0x0Eu
/**
 * @format 112
 * @param status
 * @param num_hci_command_packets
 * @param command_opcode
 */
#define HCI_EVENT_COMMAND_STATUS                           0x0Fu

struct hci_event_header
{
    u8 opcode;
    u8 parameter_len;
    u8 paramters[0];
}__attribute__((packed));

struct hci_event_command_complete
{
    u8 num_hci_command_packets;
    u16 command_opcode;
    u8 return_parameters[0];
}__attribute__((packed));

struct hci_event_command_status
{
    u8 status;
    u8 num_hci_command_packets;
    u16 command_opcode;
}__attribute__((packed));



#endif
