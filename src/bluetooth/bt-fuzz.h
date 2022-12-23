#ifndef BT_FUZZ_H
#define BT_FUZZ_H

#include "../../include/types.h"
#include "BTFuzzState.h"


extern "C" inline void bt_fuzz_reset_state()
{
    BTFuzzState::get()->reset();
}

extern "C" bool bt_fuzz_one(u8* item_buf, u32* item_len, u8* hci_trace_buf, u32 hci_trace_len, bool reset);

#endif
