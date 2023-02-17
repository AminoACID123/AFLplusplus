#include "../../../include/types.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include "os/os.h"
#include "nimble/ble.h"
#include "nimble/nimble_npl.h"
#include "nimble/nimble_port.h"
#include "host/ble_gap.h"

#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/ans/ble_svc_ans.h"
#include "services/ias/ble_svc_ias.h"
#include "services/lls/ble_svc_lls.h"
#include "services/tps/ble_svc_tps.h"

static struct ble_npl_task s_task_host;
static struct ble_npl_task s_task_hci;

#define TASK_DEFAULT_PRIORITY       1
#define TASK_DEFAULT_STACK          NULL
#define TASK_DEFAULT_STACK_SIZE     400

void ble_store_ram_init();
void send_init_packets();
void *ble_host_task(void* param);

extern u32 init_packets;
extern u32 packet_to_send;
extern u32 packet_sent;

int main(int argc, char *argv[])
{
    int ret = 0;

    nimble_port_init();

    /* This example provides GATT Alert service */
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_ans_init();
    ble_svc_ias_init();
    ble_svc_lls_init();
    ble_svc_tps_init();

    /* XXX Need to have template for store */
    ble_store_ram_init();

    /* Create task which handles default event queue for host stack. */
    ble_npl_task_init(&s_task_host, "ble_host", ble_host_task,
                      NULL, TASK_DEFAULT_PRIORITY, BLE_NPL_TIME_FOREVER,
                      TASK_DEFAULT_STACK, TASK_DEFAULT_STACK_SIZE);

    // send_init_packets();
    while(!ble_hs_synced());
    ble_addr_t addr = {
        .type = 0,
        .val = {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
    };
    struct ble_gap_conn_params param;
    ble_gap_connect(0, &addr, 100, &param, NULL, NULL);
    pthread_exit(&ret);

}
