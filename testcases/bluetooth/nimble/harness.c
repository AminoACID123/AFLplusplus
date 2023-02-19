#include "host/ble_gap.h"
#include "stdlib.h"
#include "string.h"
#define MAX_INPUT 10
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
void *arg_in[MAX_INPUT];
extern u8* __afl_area3_ptr;
void operation0() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  ble_addr_t addr;
  addr.type = *_i0;
  memcpy(addr.val, _i2, 6);
  ble_gap_connect(*_i1, &addr, *(int*)_i3, (struct ble_gap_conn_params *)_i4, NULL, NULL);
}

typedef void (*fun_ptr)();
fun_ptr FUZZ_LIST[] = {
  &operation0
};

