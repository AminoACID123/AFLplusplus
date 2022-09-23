
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "../../../include/config.h"
#include "btstack_run_loop.h"
#include "hci_cmd.h"
#include "hci_transport.h"
#include "btstack_config.h"
#include "ble/le_device_db_tlv.h"
#include "classic/btstack_link_key_db_tlv.h"
#include "btstack_tlv_posix.h"
#include "btstack_event.h"

extern char* __afl_area2_ptr;
extern int log_ptr;
//void (*fuzz_packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size);


static char* BUF;
static int SIZE;
static int POS;



extern char* arg_in[];
extern char* arg_out[];
extern char* context[];

typedef void (*fun_ptr)(char **, char **);
extern fun_ptr FUZZ_LIST[];

/*
field                   bytes
----------------------------------
harness_idx             4
arg_in_count            4
arg1_idx                4
arg1_len                4
arg1_data               --
arg_out_count           4
arg1_idx                4

*/

void execute_api(char *buf, int size) {

  int harness_idx = *(int*)(buf + 1);

  *(int*)(__afl_area2_ptr + log_ptr) = 1;
  log_ptr += 4;
  __afl_area2_ptr[log_ptr++] = F_API;

  int arg_in_count, arg_out_count;

  arg_in_count = *(int*)(buf + 5);

  int pos = 9;

  for(int i=0;i<arg_in_count;i++){
    int arg_idx = *(int*)(buf + pos);
    pos += 4;
    if (arg_idx != -1) {
      int len = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_in[i] = (char*)(buf + pos);
      pos += len;
    } else {
      arg_in[i] = context[arg_idx];
    }
  }

  arg_out_count = *(int *)(buf + pos);
  pos += 4;

  for(int i=0;i<arg_out_count;i++){
      int idx = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_out[i] = context[idx];
  }
  
  FUZZ_LIST[harness_idx](arg_in, arg_out);
}

void execute_hci(char* hci_packet_in, int size){
    int packet_len;
    switch(hci_packet_in[0]){
        case HCI_EVENT_PACKET:
            packet_len = hci_packet_in[2] + 3;
            break;
        case HCI_ACL_DATA_PACKET:
            packet_len = little_endian_read_16(hci_packet_in, 3) + 5;
            break;
        default:
            return;
    }
    *(int*)(__afl_area2_ptr + log_ptr) = size;
    log_ptr += 4;
    memcpy(__afl_area2_ptr + log_ptr, hci_packet_in, size);
    log_ptr += size;

    fuzz_packet_handler(hci_packet_in[0], &hci_packet_in[1], packet_len-1);
}

bool execute_one(){
    if(POS >= SIZE)
        return false;

    int size = *(int*)(BUF + POS);
    POS += 4;
    if(BUF[POS] == F_API)
        execute_api(BUF + POS, size);
    else
        execute_hci(BUF + POS, size); 
    POS += size;
    return true;
}


#define TLV_DB_PATH_PREFIX "/tmp/btstack_"
#define TLV_DB_PATH_POSTFIX ".tlv"
static char tlv_db_path[100];
static const btstack_tlv_t * tlv_impl;
static btstack_tlv_posix_t   tlv_context;
static bd_addr_t             local_addr;
static btstack_packet_callback_registration_t hci_event_callback_registration;
static void packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
    if (packet_type != HCI_EVENT_PACKET) return;
    switch (hci_event_packet_get_type(packet)){
        case BTSTACK_EVENT_STATE:
            switch(btstack_event_state_get_state(packet)){
                case HCI_STATE_WORKING:
                    gap_local_bd_addr(local_addr);
                    printf("BTstack up and running on %s.\n", bd_addr_to_str(local_addr));
                    btstack_strcpy(tlv_db_path, sizeof(tlv_db_path), TLV_DB_PATH_PREFIX);
                    btstack_strcat(tlv_db_path, sizeof(tlv_db_path), bd_addr_to_str_with_delimiter(local_addr, '-'));
                    btstack_strcat(tlv_db_path, sizeof(tlv_db_path), TLV_DB_PATH_POSTFIX);
                    tlv_impl = btstack_tlv_posix_init_instance(&tlv_context, tlv_db_path);
                    btstack_tlv_set_instance(tlv_impl, &tlv_context);
#ifdef ENABLE_CLASSIC
                    hci_set_link_key_db(btstack_link_key_db_tlv_get_instance(tlv_impl, &tlv_context));
#endif    
#ifdef ENABLE_BLE
                    le_device_db_tlv_configure(tlv_impl, &tlv_context);
#endif                 
            }
    }
}

void stack_init(){
    
    btstack_memory_init();

    btstack_run_loop_init(btstack_run_loop_fuzz_get_instance());

    hci_init(hci_transport_fuzz_instance(), NULL);

    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    l2cap_init();

    gatt_client_init();

    sm_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);

    send_initial_packets();
}

void stack_execute(char* buf, int size){
    BUF = buf;
    SIZE = size;
    POS = 0;
    btstack_run_loop_execute();
}
