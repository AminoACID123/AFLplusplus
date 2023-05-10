#include "hci_transport_fuzz.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// data source for integration with BTstack Runloop
static btstack_data_source_t transport_data_source;
static uint8_t packet_in[SOCKET_BUFFER_SIZE];

static void (*fuzz_packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size);

static void hci_fuzz_ds_process(btstack_data_source_t *ds, btstack_data_source_callback_type_t callback_type)
{
    if (ds->source.fd < 0)
        return;
    if (callback_type == DATA_SOURCE_CALLBACK_READ)
    {
        int len = read(ds->source.fd, packet_in, SOCKET_BUFFER_SIZE);
        if (len == SOCKET_BUFFER_SIZE)
            perror("Socket Buffer Full");
        fuzz_packet_handler(packet_in[0], &packet_in[1], len - 1);
    }
}

static int hci_transport_fuzz_can_send_now(uint8_t packet_type)
{
    return 1;
}

static int hci_transport_fuzz_send_packet(uint8_t packet_type, uint8_t *packet, int size)
{
    uint8_t *buffer = &packet[-1];
    uint32_t buffer_size = size + 1;
    buffer[0] = packet_type;
    write(transport_data_source.source.fd, buffer, buffer_size);
    printf("Sent packet %d\n", packet_type);

    static const uint8_t packet_sent_event[] = {HCI_EVENT_TRANSPORT_PACKET_SENT, 0};
    fuzz_packet_handler(HCI_EVENT_PACKET, (uint8_t *)&packet_sent_event[0], sizeof(packet_sent_event));

    return 0;
}

static int hci_transport_fuzz_open(void)
{
    struct sockaddr_un addr;

    // Create a new server socket with domain: AF_UNIX, type: SOCK_STREAM,
    // protocol: 0
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);

    // Make sure socket's file descriptor is legit.
    if (sfd == -1)
    {
        perror("Error creating socket");
    }


    // Zero out the address, and set family and path.
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, HCI_SOCKET);

    if (connect(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1)
    {
        perror("Error connecting to socket");
    }

    // set up data_source
    btstack_run_loop_set_data_source_fd(&transport_data_source, sfd);
    btstack_run_loop_set_data_source_handler(&transport_data_source, &hci_fuzz_ds_process);
    btstack_run_loop_add_data_source(&transport_data_source);
    btstack_run_loop_enable_data_source_callbacks(&transport_data_source, DATA_SOURCE_CALLBACK_READ);

    return 0;
}

static int hci_transport_fuzz_close(void)
{
    close(transport_data_source.source.fd);
    return 0;
}

static void hci_transport_fuzz_register_packet_handler(void (*handler)(uint8_t packet_type, uint8_t *packet,
                                                                       uint16_t size))
{
    fuzz_packet_handler = handler;
}

static const hci_transport_t hci_transport_fuzz = {
    /* const char * name; */ "fuzz",
    /* void   (*init) (const void *transport_config); */ NULL,
    /* int    (*open)(void); */ &hci_transport_fuzz_open,
    /* int    (*close)(void); */ &hci_transport_fuzz_close,
    /* void   (*register_packet_handler)(void (*handler)(...); */
    &hci_transport_fuzz_register_packet_handler,
    /* int    (*can_send_packet_now)(uint8_t packet_type); */
    &hci_transport_fuzz_can_send_now,
    /* int    (*send_packet)(...); */ &hci_transport_fuzz_send_packet,
    /* int    (*set_baudrate)(uint32_t baudrate); */ NULL,
    /* void   (*reset_link)(void); */ NULL,
    /* void   (*set_sco_config)(uint16_t voice_setting, int num_connections); */
    NULL,
};

const hci_transport_t *hci_transport_fuzz_instance()
{
    return &hci_transport_fuzz;
}

void send_initial_packets()
{


    // fuzz_packet_handler(HCI_EVENT_PACKET, packet1, sizeof(packet1));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet2, sizeof(packet2));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet3, sizeof(packet3));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet4, sizeof(packet4));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet5, sizeof(packet5));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet6, sizeof(packet6));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet7, sizeof(packet7));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet8, sizeof(packet8));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet9, sizeof(packet9));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet10, sizeof(packet10));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet11, sizeof(packet11));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet12, sizeof(packet12));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet13, sizeof(packet13));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet14, sizeof(packet14));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet15, sizeof(packet15));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet16, sizeof(packet16));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet17, sizeof(packet17));

    // fuzz_packet_handler(HCI_EVENT_PACKET, packet18, sizeof(packet18));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet19, sizeof(packet19));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet20, sizeof(packet20));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));

    // fuzz_packet_handler(HCI_EVENT_PACKET, packet22, sizeof(packet22));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet23, sizeof(packet23));
    // fuzz_packet_handler(HCI_EVENT_PACKET, packet24, sizeof(packet24));
}