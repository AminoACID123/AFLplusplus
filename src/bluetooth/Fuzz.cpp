

#include <assert.h>

#include <vector>

#include "../../include/bluetooth.h"
#include "BTFuzzState.h"
#include "Operation.h"
#include "Hci.h"

using namespace std;


extern "C" void bt_enable_sema(bool sema)
{
  BTFuzzState::get()->enable_sema(sema);
}

/// @brief Given an input item sequence and its corresponding output, append one new item to the sequence
/// @param items Input item sequence
/// @param size Size of \param items
/// @param out1 HCI output buffer
/// @param out2 Runtime buffer
/// @param reset Whether to reset BTFuzzState using \param state
/// @param state
extern "C" u32 bt_fuzz_one(u8* items, u32 size, u8* out1, u8* out2, bool reset, u8* state)
{
  BTFuzzState* bt = BTFuzzState::get();
  if(reset){
    bt->reset();
    if(state)
      bt->deserialize(state);
  }
  bt->step_one(items, size, out1, out2);
}

extern "C" u32 bt_serialize_state(u8* buf)
{
  return BTFuzzState::get()->serialize(buf);
}

extern "C" void bt_deserialize_state(u8* buf)
{
  BTFuzzState::get()->deserialize(buf);
}

extern "C" void bt_rand_init(s32 fd)
{
  rand_init(fd);
}

extern "C" u32 bt_init_corpus_count()
{
  return 2 *(operations.size() + sEvt.size() + sLeEvt.size());
}