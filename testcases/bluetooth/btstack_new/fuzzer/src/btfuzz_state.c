#include "btfuzz_state.h"
#include <stdlib.h>

btfuzz_state_t* btfuzz;

void btfuzz_state_init()
{
  if (!btfuzz){
    btfuzz = calloc(1, sizeof(btfuzz_state_t));
  }
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