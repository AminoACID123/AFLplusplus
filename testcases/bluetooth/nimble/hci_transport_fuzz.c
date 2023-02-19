#include "../../../include/types.h"
#include "../../../include/bluetooth.h"
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

extern item_t* pItem;
extern item_t* pItem_end;
extern item_t* pHCIItem;

void *ble_transport_alloc_evt(int discardable);
int ble_transport_to_hs_evt_impl(void *buf);
void ble_transport_free(void *buf);

#define INIT_PACKETS 15

u32 packet_to_send = 0;
u32 packet_sent = 0;


u8 event0[] = {0x0E, 0x04, 0x01, 0x03, 0x0c, 0x00};  // BT_HCI_CMD_RESET
u8 event1[] = {0x0E, 0x0C, 0x01, 0x01, 0x10, 0x00, 0x0C, 0xFF, 0xFF, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF};  // BT_HCI_CMD_READ_LOCAL_VERSION
u8 event2[] = {0x0E, 0x0c, 0x01, 0x03, 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // BT_HCI_CMD_READ_LOCAL_FEATURES
u8 event3[] = {0x0E, 0x04, 0x01, 0x01, 0x0c, 0x00};  // BT_HCI_CMD_SET_EVENT_MASK
u8 event4[] = {0x0E, 0x04, 0x01, 0x63, 0x0c, 0x00};  // BT_HCI_CMD_SET_EVENT_MASK_PAGE2
u8 event5[] = {0x0E, 0x04, 0x01, 0x01, 0x20, 0x00};  // BT_HCI_CMD_LE_SET_EVENT_MASK
u8 event6[] = {0x0E, 0x07, 0x01, 0x02, 0x20, 0x00, 0xff, 0x01, 0xff};  // BT_HCI_CMD_LE_READ_BUFFER_SIZE
u8 event7[] = {0x0E, 0x0c, 0x01, 0x03, 0x20, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  // BT_HCI_CMD_LE_READ_LOCAL_FEATURES
u8 event8[] = {0x0E, 0x0a, 0x01, 0x09, 0x10, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};  // BT_HCI_CMD_READ_BD_ADDR
u8 event9[] = {0x0E, 0x04, 0x01, 0x2d, 0x20, 0x00};  // BT_HCI_CMD_LE_SET_RESOLV_ENABLE
u8 event10[] = {0x0E, 0x04, 0x01, 0x29, 0x20, 0x00};  // BT_HCI_CMD_LE_CLEAR_RESOLV_LIST
u8 event11[] = {0x0E, 0x04, 0x01, 0x2d, 0x20, 0x00};  // BT_HCI_CMD_LE_SET_RESOLV_ENABLE  
u8 event12[] = {0x0E, 0x04, 0x01, 0x0a, 0x20, 0x00};  // BT_HCI_CMD_LE_SET_ADV_ENABLE
u8 event13[] = {0x0E, 0x04, 0x01, 0x27, 0x20, 0x00};  // BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST
u8 event14[] = {0x0E, 0x04, 0x01, 0x4e, 0x20, 0x00};  // BT_HCI_CMD_LE_SET_PRIV_MODE

u8* init_evts[] = {
    event0, event1, event2, event3, event4, event5, event6, event7, event8, 
    event9, event10, event11, event12, event13, event14, 
};

void nimble_host_task(void *param)
{
    nimble_port_run();
}

void *ble_host_task(void *param)
{
    nimble_host_task(param);
    return NULL;
}

void send_to_hs_evt(u8 *buf, u32 len)
{
    int rc;
    u8 *data = ble_transport_alloc_evt(0);
    memcpy(data, buf, len);
    rc = ble_transport_to_hs_evt_impl(data);
    if (rc)
        ble_transport_free(data);
    return;
}

void send_to_hs_acl(u8* buf, u32 len)
{
    struct os_mbuf *m = ble_transport_alloc_acl_from_ll();
    if (os_mbuf_append(m, buf, len)) {
        os_mbuf_free_chain(m);
        return;
    }
    ble_transport_to_hs_acl(m);
}

int ble_transport_to_ll_cmd_impl(void *buf)
{
    printf("HCI Command: 0x%02x%02x\n", ((u8 *)buf)[1], ((u8 *)buf)[0]);
    if(pHCIItem){
        hci_command_t* cmd = (hci_command_t*)pHCIItem->data;
        cmd->flag = HCI_COMMAND_DATA_PACKET;
        memcpy(&cmd->opcode, buf, *((u8*)buf + 2) + 3);
        pHCIItem->size = cmd->len + sizeof(hci_command_t);
        pHCIItem = (item_t*)&pHCIItem->data[pHCIItem->size];
        pHCIItem->size = 0;
    }

    ble_transport_free(buf);
    if(packet_sent < INIT_PACKETS){
        send_to_hs_evt(init_evts[packet_sent], init_evts[packet_sent][1] + 1);
        ++packet_sent;
    }else if(&pItem->data[pItem->size] < pItem_end){
        item_t* next = (item_t*)&pItem->data[pItem->size];
        if(next->data[0] == HCI_EVENT_PACKET){
            send_to_hs_evt(next->data + 1, next->size - 1);
            pItem = next;
        }
    }else{
        exit(0);
    }
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
