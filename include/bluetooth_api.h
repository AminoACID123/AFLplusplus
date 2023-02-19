#include "types.h"

/*Init*/

void init_stack_hci(const char* bc_file, const char* stack);

void parse_operation(const char *in_file, const char *out_file);

void bt_rand_init(s32 fd);

u32 bt_set_buf(u8* hci, u8* rt);

void bt_enable_sema(bool);

bool bt_sema_enabled();

/*Fuzz*/
u32 bt_fuzz_one(u8* buf);

void bt_restore_state();

u32 bt_serialize_state(u8 *buf);

void bt_deserialize_state(u8 *buf);

const char* bt_get_op_str();

void bt_sync_hci();