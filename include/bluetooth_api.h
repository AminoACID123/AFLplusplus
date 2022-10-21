#include "types.h"

/*******************
* Harness API Begin*
********************/
void parse_harness(const char* in_file, const char* out_file); 

void generate_random_harness(u32 idx, u32 seed, u8* out_buf);

u32 get_total_harness();
/******************
* Harness API End *
*******************/

/***************
* HCI API Begin*
****************/
bool reply_with_status(u16 opcode);

bool reply_with_complete(u16 opcode);

u32 get_total_hci();

u32 get_total_hci_le();

void generate_random_hci(u32 seed, u8* evt, u8* le_evt);

void init_stack_hci(const char *bc);
/**************
* HCI API End *
***************/