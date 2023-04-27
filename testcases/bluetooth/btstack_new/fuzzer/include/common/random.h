#ifndef BTFUZZ_RAND_H
#define BTFUZZ_RAND_H

#include "type.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

void rand_init();

u32 rand_below(u32 limit);

void rand_fill(u8* buf, u32 bytes);

#endif