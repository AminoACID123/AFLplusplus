#include "hci_transport_fuzz.h"
#include "btstack_run_loop.h"
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

extern u_int8_t* __afl_area2_ptr;
void (*fuzz_packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size);
static uint8_t hci_packet_out[1 + HCI_OUTGOING_PACKET_BUFFER_SIZE]; // packet type + max(acl header + acl payload, cmd header   +   cmd data)
static uint8_t hci_packet_in[1 + HCI_INCOMING_PACKET_BUFFER_SIZE]; // packet type + max(acl header + acl payload, event header + event data)
static btstack_data_source_t* ds;

static int hci_transport_fuzz_set_baudrate(uint32_t baudrate)
{ 
    return 0;
}

static int hci_transport_fuzz_can_send_now(uint8_t packet_type)
{ 
    return 1;
}

static int hci_transport_fuzz_send_packet(uint8_t packet_type, uint8_t * packet, int size){

    // preapare packet
    // hci_packet_out[0] = packet_type;
    // memcpy(&hci_packet_out[1], packet, size);

    *__afl_area2_ptr = packet_type;
    memcpy(&__afl_area2_ptr + 1, packet, size);

    static const uint8_t packet_sent_event[] = { HCI_EVENT_TRANSPORT_PACKET_SENT, 0};
    packet_handler(HCI_EVENT_PACKET, (uint8_t *) &packet_sent_event[0], sizeof(packet_sent_event));
    
    return 0;
}

static void hci_transport_fuzz_init(const void * transport_config){ }

static inline uint16_t little_endian_read_16(const uint8_t * buffer, int position){
    return (uint16_t)(((uint16_t) buffer[position]) | (((uint16_t)buffer[position+1]) << 8));
}

static void fuzz_process(btstack_data_source_t *_ds, btstack_data_source_callback_type_t callback_type) {
    if (ds->source.fd == 0) return;

    // read up to bytes_to_read data in
    ssize_t bytes_read = read(ds->source.fd, &hci_packet_in[0], sizeof(hci_packet_in));

    if (bytes_read == 0) return;

    // iterate over packets
    uint16_t pos = 0;
    while (pos < bytes_read) {
        uint16_t packet_len;
        switch(hci_packet_in[pos]){
            case HCI_EVENT_PACKET:
                packet_len = hci_packet_in[pos+2] + 3;
                break;
            case HCI_ACL_DATA_PACKET:
            
                 packet_len = little_endian_read_16(hci_packet_in, pos + 3) + 5;
                 break;
            default:
                // log_error("h4_process: invalid packet type 0x%02x\n", hci_packet_in[pos]);
                return;
        }

       // if(hci_packet_in[pos+4] == 0x01 && hci_packet_in[pos+5] == 0x13)
      //  {
            printf("%02x %02x\n", hci_packet_in[pos+4], hci_packet_in[pos+5]);
      //  }
        packet_handler(hci_packet_in[pos], &hci_packet_in[pos+1], packet_len-1);
        pos += packet_len;
    }
}

static int hci_transport_fuzz_open(void)
{
    return 0;
}


static int hci_transport_fuzz_close(void)
{ 
    return 0; 
}

static void hci_transport_fuzz_register_packet_handler(void (*handler)(uint8_t packet_type, uint8_t *packet, uint16_t size))
{
    fuzz_packet_handler = handler;
}

static const hci_transport_t hci_transport_fuzz = {
        /* const char * name; */                                        "FUZZ",
        /* void   (*init) (const void *transport_config); */            NULL,
        /* int    (*open)(void); */                                     &hci_transport_fuzz_open,
        /* int    (*close)(void); */                                    &hci_transport_fuzz_close,
        /* void   (*register_packet_handler)(void (*handler)(...); */   &hci_transport_fuzz_register_packet_handler,
        /* int    (*can_send_packet_now)(uint8_t packet_type); */       &hci_transport_fuzz_can_send_now,
        /* int    (*send_packet)(...); */                               &hci_transport_fuzz_send_packet,
        /* int    (*set_baudrate)(uint32_t baudrate); */                NULL,
        /* void   (*reset_link)(void); */                               NULL,
        /* void   (*set_sco_config)(uint16_t voice_setting, int num_connections); */ NULL,
};


const hci_transport_t* hci_transport_fuzz_instance(){
    return &hci_transport_fuzz;
}

static void run_loop_posix_execute(void) {

    struct timeval * timeout;
    struct timeval tv;
    uint32_t now_ms;

    while (1) {

        execute(__afl_area2_ptr);
        // process timers
        now_ms = btstack_run_loop_posix_get_time_ms();
        btstack_run_loop_base_process_timers(now_ms);
    }
}

void execute_hci(char* buf, int size){

}

void stack_init(){
    
    btstack_memory_init();
    
    btstack_run_loop_t* run_loop = btstack_run_loop_posix_get_instance();

    run_loop->execute = &run_loop_posix_execute;

    btstack_run_loop_init(btstack_run_loop_posix_get_instance());

    hci_init(hci_transport_fuzz_instance(), NULL);

    l2cap_init();

    gatt_client_init();

    sm_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);
}

void stack_execute(){
    btstack_run_loop_execute();
}
