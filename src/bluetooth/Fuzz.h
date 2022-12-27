#ifndef BT_FUZZ_H
#define BT_FUZZ_H

#include "../../include/types.h"
#include "BTFuzzState.h"


extern "C" inline void bt_fuzz_reset_state()
{
    BTFuzzState::get()->reset();
}

extern "C" u32 bt_fuzz_one(u8* items, u32 size, u8* out1, u8* out2, bool reset, u8* state);

#endif
