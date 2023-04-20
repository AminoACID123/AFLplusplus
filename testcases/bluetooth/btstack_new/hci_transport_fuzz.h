#ifndef AC935CFB_E82F_481D_A1A4_6CA86518BF3A
#define AC935CFB_E82F_481D_A1A4_6CA86518BF3A

#include "btstack_run_loop.h"
#include "hci_cmd.h"
#include "hci_transport.h"

#define HCI_SOCKET "/tmp/hci.sock"
#define SOCKET_BUFFER_SIZE 1024 * 1024

const hci_transport_t *hci_transport_fuzz_instance(void);

#endif /* AC935CFB_E82F_481D_A1A4_6CA86518BF3A */
