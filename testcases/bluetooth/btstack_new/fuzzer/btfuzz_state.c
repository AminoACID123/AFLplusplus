#include "btfuzz.h"
#include "btfuzz_bluetooth.h"
#include <aio.h>

typedef struct btfuzz_hci_entry {
    u8 enabled;
}btfuzz_hci_entry;

typedef struct btfuzz_state {
  u8 packet_in;
  size_t paket_size;
}btfuzz_state;

static btfuzz_state state;

void bs_init()
{

}

void bs_set_event_mask(u8* mask)
{

}

void bs_set_event_mask2(u8* mask)
{

}

void bs_set_le_event_mask(u8* mask)
{

}