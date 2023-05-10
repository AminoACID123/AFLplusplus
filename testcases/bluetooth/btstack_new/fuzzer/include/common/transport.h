#ifndef BTFUZZ_TRANSPORT_H
#define BTFUZZ_TRANSPORT_H

#include "common/type.h"

void dump_packet(char *msg, u8 type, void *packet, u32 len);
void send_packet(u8 type, void *packet, u32 len);


#endif /* BTFUZZ_TRANSPORT_H */
