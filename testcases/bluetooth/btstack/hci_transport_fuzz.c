#include "btstack_run_loop.h"
#include "hci_cmd.h"
#include "hci_transport.h"
#include "stdlib.h"
#include "../../../include/config.h"

extern char* __afl_area2_ptr;
int log_ptr;
void (*fuzz_packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size);

static int hci_transport_fuzz_set_baudrate(uint32_t baudrate)
{ 
    return 0;
}

static int hci_transport_fuzz_can_send_now(uint8_t packet_type)
{ 
    return 1;
}

static void print_packet(uint8_t packet_type, uint8_t* packet, int size){
    char* packet_type_str;
    switch (packet_type)
    {
    case HCI_COMMAND_DATA_PACKET: packet_type_str = "HCI_COMMAND"; break;
    case HCI_EVENT_PACKET: packet_type_str = "HCI_EVENT"; break;
    case HCI_ACL_DATA_PACKET: packet_type_str = "HCI_ACL"; break;
    default:
        packet_type_str = "UNKNOWN_PACKET"; break;  
    }
    printf("%s: ", packet_type_str);
    for(int i=0;i<size;i++)
        printf("%02x ", packet[i]);
    printf("\n");
}

static int hci_transport_fuzz_send_packet(uint8_t packet_type, uint8_t * packet, int size){

    // preapare packet
    // hci_packet_out[0] = packet_type;
    // memcpy(&hci_packet_out[1], packet, size);

    print_packet(packet_type, packet, size);

    *(int*)(__afl_area2_ptr + log_ptr) = size + 1;
    log_ptr += 4;
    __afl_area2_ptr[log_ptr++] = packet_type;
    memcpy(&__afl_area2_ptr + log_ptr, packet, size);
    log_ptr += size;

    static const uint8_t packet_sent_event[] = { HCI_EVENT_TRANSPORT_PACKET_SENT, 0};
    fuzz_packet_handler(HCI_EVENT_PACKET, (uint8_t *) &packet_sent_event[0], sizeof(packet_sent_event));
    
    return 0;
}

static void hci_transport_fuzz_init(const void * transport_config){ }

// static inline uint16_t little_endian_read_16(const uint8_t * buffer, int position){
//     return (uint16_t)(((uint16_t) buffer[position]) | (((uint16_t)buffer[position+1]) << 8));
// }

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