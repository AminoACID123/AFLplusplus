#include "../../../include/types.h"
#include "nimble/nimble_npl.h"
#include "nimble/nimble_port.h"
#include "os/os.h"
#include "services/ans/ble_svc_ans.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/ias/ble_svc_ias.h"
#include "services/lls/ble_svc_lls.h"
#include "services/tps/ble_svc_tps.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

u32 init_packets = 15;
u32 packet_to_send = 0;
u32 packet_sent = 0;

void nimble_host_task(void *param)
{
    nimble_port_run();
}

void *ble_host_task(void *param)
{
    nimble_host_task(param);
    return NULL;
}

void send_evt(u8 *buf, u32 len)
{
    int rc;
    u8 *data = ble_transport_alloc_evt(0);
    memcpy(data, buf, len);
    rc = ble_transport_to_hs_evt_impl(data);
    if (rc)
        ble_transport_free(data);
    return;
}

void send_init_packets()
{
    // BT_HCI_CMD_RESET
    u8 packet1[] = {0x0E, 0x04, 0x01, 0x03, 0x0c, 0x00};
    // BT_HCI_CMD_READ_LOCAL_VERSION
    u8 packet2[] = {0x0E, 0x0C, 0x01, 0x01, 0x10, 0x00, 0x0C, 0xFF, 0xFF, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF};
    // BT_HCI_CMD_READ_LOCAL_FEATURES
    u8 packet3[] = {0x0E, 0x0c, 0x01, 0x03, 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // BT_HCI_CMD_SET_EVENT_MASK
    u8 packet4[] = {0x0E, 0x04, 0x01, 0x01, 0x0c, 0x00};
    // BT_HCI_CMD_SET_EVENT_MASK_PAGE2
    u8 packet5[] = {0x0E, 0x04, 0x01, 0x63, 0x0c, 0x00};
    // BT_HCI_CMD_LE_SET_EVENT_MASK
    u8 packet6[] = {0x0E, 0x04, 0x01, 0x01, 0x20, 0x00};
    // BT_HCI_CMD_LE_READ_BUFFER_SIZE
    u8 packet7[] = {0x0E, 0x07, 0x01, 0x02, 0x20, 0x00, 0xff, 0x01, 0xff};
    // BT_HCI_CMD_LE_READ_LOCAL_FEATURES
    u8 packet8[] = {0x0E, 0x0c, 0x01, 0x03, 0x20, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // BT_HCI_CMD_READ_BD_ADDR
    u8 packet9[] = {0x0E, 0x0a, 0x01, 0x09, 0x10, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    // BT_HCI_CMD_LE_SET_RESOLV_ENABLE
    u8 packet10[] = {0x0E, 0x04, 0x01, 0x2d, 0x20, 0x00};
    // BT_HCI_CMD_LE_CLEAR_RESOLV_LIST
    u8 packet11[] = {0x0E, 0x04, 0x01, 0x29, 0x20, 0x00};
    // BT_HCI_CMD_LE_SET_RESOLV_ENABLE  
    u8 packet12[] = {0x0E, 0x04, 0x01, 0x2d, 0x20, 0x00};
    // BT_HCI_CMD_LE_SET_ADV_ENABLE
    u8 packet13[] = {0x0E, 0x04, 0x01, 0x0a, 0x20, 0x00};
    // BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST
    u8 packet14[] = {0x0E, 0x04, 0x01, 0x27, 0x20, 0x00};
    // BT_HCI_CMD_LE_SET_PRIV_MODE
    u8 packet15[] = {0x0E, 0x04, 0x01, 0x4e, 0x20, 0x00};

    while (packet_sent != init_packets)
    {
        if (packet_sent == packet_to_send)
            continue;
        switch (packet_to_send){
            case 1: send_evt(packet1, sizeof(packet1)); break;
            case 2: send_evt(packet2, sizeof(packet2)); break;
            case 3: send_evt(packet3, sizeof(packet3)); break;
            case 4: send_evt(packet4, sizeof(packet4)); break;
            case 5: send_evt(packet5, sizeof(packet5)); break;
            case 6: send_evt(packet6, sizeof(packet6)); break;
            case 7: send_evt(packet7, sizeof(packet7)); break;
            case 8: send_evt(packet8, sizeof(packet8)); break;
            case 9: send_evt(packet9, sizeof(packet9)); break;
            case 10: send_evt(packet10, sizeof(packet10)); break;
            case 11: send_evt(packet11, sizeof(packet11)); break;
            case 12: send_evt(packet12, sizeof(packet12)); break;
            case 13: send_evt(packet13, sizeof(packet13)); break;
            case 14: send_evt(packet14, sizeof(packet14)); break;
            case 15: send_evt(packet15, sizeof(packet15)); break;
            default: 
                break;
        }
        packet_sent = packet_to_send;
    }
    while(!ble_hs_synced());
}

int ble_transport_to_ll_cmd_impl(void *buf)
{
    printf("%02x%02x\n", ((u8 *)buf)[1], ((u8 *)buf)[0]);
    ble_transport_free(buf);
    ++packet_to_send;
    return 0;
}

int ble_transport_to_ll_acl_impl(struct os_mbuf *om)
{
    os_mbuf_free_chain(om);
    return 0;
}

// int
// ble_transport_to_hs_acl_impl(struct os_mbuf *om)
// {
//     return ble_hci_trans_ll_tx(&ble_hci_tx_acl_queue, om);
// }

// int
// ble_transport_to_hs_evt_impl(void *buf)
// {
//     return ble_hci_trans_ll_evt_tx(buf);
// }
