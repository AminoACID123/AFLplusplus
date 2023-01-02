

#include <assert.h>

#include <vector>

#include "../../include/bluetooth.h"
#include "BTFuzzState.h"
#include "Operation.h"
#include "Hci.h"

using namespace std;

extern "C" void bt_rand_init(s32 fd)
{
  rand_init(fd);
}

extern "C" void bt_enable_sema(bool sema)
{
  BTFuzzState::get()->enable_sema(sema);
}

extern "C" void bt_set_buf(u8* hci, u8* rt)
{
   BTFuzzState::get()->set_buffers(hci, rt);
}

extern "C" u32 bt_serialize_state(u8* buf)
{
  return BTFuzzState::get()->serialize(buf);
}

extern "C" void bt_restore_state(u8* buf)
{
  BTFuzzState::get()->deserialize(buf);
}

extern "C" u32 bt_init_corpus_count()
{
  return 2 * (operations.size() + sEvt.size() + sLeEvt.size());
}

extern "C" void bt_step_one(u8* items, u32 size)
{
  BTFuzzState::get()->step_one(items, size);
}

extern "C" u32 bt_fuzz_one(u8* buf)
{
  return BTFuzzState::get()->fuzz_one(buf);
}
