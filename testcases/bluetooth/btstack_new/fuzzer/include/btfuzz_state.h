#ifndef BFA36BF7_8882_4C5A_9694_4DD2E7CE3276
#define BFA36BF7_8882_4C5A_9694_4DD2E7CE3276
#include "common/type.h"
#include "common/bluetooth.h"
#include "common/util.h"

typedef enum {
    // non-secure
    INITIALIZE,

    // service level enforced security
    GAP_SECURITY_MODE_2,

    // link level enforced security
    GAP_SECURITY_MODE_3,

    // service level enforced security
    GAP_SECURITY_MODE_4
}btfuzz_cur_state ;

typedef struct {
    u8  cmd_buf[sizeof(bt_hci_cmd_hdr) + 255];
    u8  evt_buf[sizeof(bt_hci_evt_hdr) + 255];
    u8* acl_buf_in;
    u8 acl_buf_out[1024];
    u16 next_handle;
    btfuzz_vector_t     connections;
}btfuzz_state_t;

extern btfuzz_state_t* btfuzz;

void btfuzz_state_init();

#endif /* BFA36BF7_8882_4C5A_9694_4DD2E7CE3276 */
