#include "types.h"

void init_stack_hci(const char* bc_file);

void parse_operation(const char *in_file, const char *out_file);

u32 bt_set_buf(u8* hci, u8* rt);

u32 bt_fuzz_one(u8* buf);

void bt_step_one(u8* items, u32 size);

u32 bt_serialize_state(u8* buf);

void bt_restore_state(u8* buf);

u32 bt_init_corpus_count();

void bt_enable_sema(bool);

void bt_rand_init(s32 fd);