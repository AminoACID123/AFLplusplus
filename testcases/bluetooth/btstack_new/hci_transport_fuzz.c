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
    /* Reset */
    uint8_t packet1[] = {0x0E, 0x04, 0x01, 0x03, 0x0c, 0x00};
    /* Read Local Version */
    uint8_t packet2[] = {0x0E, 0x0C, 0x01, 0x01, 0x10, 0x00, 0x0C, 0xFF, 0xFF, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF};
    /* Read Local Name */
    uint8_t packet3[254] = {0x0E, 0xFC, 0x01, 0x14, 0x0c, 0x00, 'F', 'U', 'Z', 'Z'};
    // Read Local Commands
    uint8_t packet4[70] = {0x0E, 0x44, 0x01, 0x02, 0x10, 0x00};
    memset(packet4 + 6, 0xFF, 64);
    // Read BD_ADDR
    uint8_t packet5[] = {0x0E, 0x0a, 0x01, 0x09, 0x10, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    // Read Buffer Size
    uint8_t packet6[] = {0x0E, 0x0B, 0x01, 0x05, 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Read Local Features
    uint8_t packet7[] = {0x0E, 0x0c, 0x01, 0x03, 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Set Event Mask
    uint8_t packet8[] = {0x0E, 0x04, 0x01, 0x01, 0x0c, 0x00};
    // Set Event Mask Page2
    uint8_t packet9[] = {0x0E, 0x04, 0x01, 0x63, 0x0c, 0x00};
    // LE Read Buffer Size V2
    uint8_t packet10[] = {0x0E, 0x0a, 0x01, 0x60, 0x20, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Write LE Host Supported
    uint8_t packet11[] = {0x0E, 0x04, 0x01, 0x6d, 0x0c, 0x00};
    // LE Set Event Mask
    uint8_t packet12[] = {0x0E, 0x04, 0x01, 0x01, 0x20, 0x00};
    // LE Read Max Data Length
    uint8_t packet13[] = {0x0E, 0x0c, 0x01, 0x2f, 0x20, 0x00, 0xFB, 0x00, 0x90, 0x42, 0xFB, 0x00, 0x90, 0x42};
    // LE Write Default Data Length
    uint8_t packet14[] = {0x0E, 0x04, 0x01, 0x24, 0x20, 0x00};
    // LE Read Accept List Size
    uint8_t packet15[] = {0x0E, 0x05, 0x01, 0x0f, 0x20, 0x00, 0xff};
    // LE Read Max Adv Data Len
    uint8_t packet16[] = {0x0E, 0x06, 0x01, 0x3a, 0x20, 0x00, 0x72, 0x06};
    // LE Set Ext Scan Params
    uint8_t packet17[] = {0x0E, 0x04, 0x01, 0x41, 0x20, 0x00};
    // LE Rand
    uint8_t packet18[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0xB8, 0x4E, 0x75, 0xC7, 0xE2, 0xBE, 0x8E, 0xAA};
    // LE Rand
    uint8_t packet19[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0xC6, 0x28, 0x81, 0xA5, 0xB9, 0xB1, 0x59, 0xFE};
    // LE Rand
    uint8_t packet20[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0x39, 0x77, 0x84, 0x1C, 0x29, 0x33, 0xEF, 0xF6};
    // LE Rand
    uint8_t packet21[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0x08, 0x4A, 0x6F, 0x0D, 0x19, 0xE4, 0x23, 0x0A};
    // LE Set Resolve Enable
    uint8_t packet22[] = {0x0E, 0x04, 0x01, 0x2d, 0x20, 0x00};
    // LE Read Resolve List Size
    uint8_t packet23[] = {0x0E, 0x05, 0x01, 0x2a, 0x20, 0x00, 0xFF};
    // LE Clear Resolve List
    uint8_t packet24[] = {0x0E, 0x04, 0x01, 0x29, 0x20, 0x00};

    fuzz_packet_handler(HCI_EVENT_PACKET, packet1, sizeof(packet1));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet2, sizeof(packet2));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet3, sizeof(packet3));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet4, sizeof(packet4));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet5, sizeof(packet5));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet6, sizeof(packet6));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet7, sizeof(packet7));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet8, sizeof(packet8));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet9, sizeof(packet9));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet10, sizeof(packet10));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet11, sizeof(packet11));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet12, sizeof(packet12));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet13, sizeof(packet13));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet14, sizeof(packet14));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet15, sizeof(packet15));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet16, sizeof(packet16));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet17, sizeof(packet17));

    fuzz_packet_handler(HCI_EVENT_PACKET, packet18, sizeof(packet18));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet19, sizeof(packet19));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet20, sizeof(packet20));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet21, sizeof(packet21));

    fuzz_packet_handler(HCI_EVENT_PACKET, packet22, sizeof(packet22));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet23, sizeof(packet23));
    fuzz_packet_handler(HCI_EVENT_PACKET, packet24, sizeof(packet24));
}