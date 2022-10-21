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


#endif
