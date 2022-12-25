

#include <assert.h>

#include <vector>

#include "../../include/bluetooth.h"
#include "BTFuzzState.h"
#include "Operation.h"

using namespace std;

static bool hci_trace_closed(u8* hci_trace, u32 max_len) {
  item_header* hdr = (item_header*)hci_trace;
  item_header* tail;
  while (hdr->size != 0 && (u8*)hdr - hci_trace < max_len) {
    tail = hdr;
    hdr = (item_header*)((u8*)hdr + hdr->size + sizeof(u32));
  }

  if (tail->size == 0)
    return true;
  else if ((u8*)hdr - hci_trace < max_len) {
    switch (tail->flag) {
      case HCI_EVENT_PACKET:
        return false;
      case HCI_COMMAND_DATA_PACKET:
        return true;
      case HCI_ACL_DATA_PACKET:
      case HCI_SCO_DATA_PACKET:
      case HCI_ISO_DATA_PACKET:
        return true;
      default:
        break;
    }
  }
  assert(false && "hci_trace buffer overflow");
  return true;
}

void split_items(vector<item_header*>& res, u8* buf, u32 len) {
  item_header* p = (item_header*)buf;
  while (p->size != 0 && (u8*)p - buf < len) {
    res.push_back(p);
    p = (item_header*)((u8*)p + p->size + sizeof(u32));
  }
}

extern "C" bool bt_fuzz_one(u8* item_buf, u32* item_len, u8* hci_trace_buf, u32 hci_trace_len, bool reset) {
  bool cont = true;
  BTFuzzState* bt = BTFuzzState::get();
  vector<item_header*> items;
  vector<item_header*> hci_trace;

    split_items(items, item_buf, *item_len);
    split_items(hci_trace, hci_trace_buf, hci_trace_len);

    if(reset){
        BTFuzzState::get()->reset(); 
    } 


  u32 rand = bt->rand_below(100);
  if (rand <= 20) {
  } else {
  }
}
