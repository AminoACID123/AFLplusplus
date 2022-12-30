#include "types.h"

void init_stack_hci(const char* bc_file);

void parse_operation(const char *in_file, const char *out_file);

u32 bt_fuzz_one(u8* items, u32 size, u8* out1, u8* out2, bool reset, u8* state);

u32 bt_serialize_state(u8* buf);

u32 bt_init_corpus_count();

void bt_deserialize_state(u8* buf);

void bt_enable_sema(bool);

void bt_rand_init(s32 fd);