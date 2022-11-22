#include "types.h"

/*******************
* Operation API Begin*
********************/
void parse_operation(const char* in_file, const char* out_file); 

void generate_random_operation(u32 idx, u32 seed, u8* out_buf);


u32 get_total_operation();
/******************
* Operation API End *
*******************/

/***************
* Packet API Begin*
****************/
bool reply_with_status(u16 opcode);

bool reply_with_complete(u16 opcode);

u32 get_total_hci();

u32 get_total_hci_le();

void generate_random_event(u32 seed, u8* evt, u8* le_evt);

void init_stack_hci(const char *bc);
/**************
* HCI API End *
***************/