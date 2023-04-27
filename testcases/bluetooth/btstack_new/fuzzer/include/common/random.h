#ifndef BTFUZZ_RAND_H
#define BTFUZZ_RAND_H

#include "btfuzz_type.h"

void rand_init();

u32 rand_below(u32 limit);

void rand_fill(u8* buf, u32 bytes);

#endif