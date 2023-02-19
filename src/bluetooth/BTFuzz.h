#ifndef B143D1D5_36EB_4829_B56D_55AC37ABB19B
#define B143D1D5_36EB_4829_B56D_55AC37ABB19B


#include "assert.h"
#include "../../include/types.h"
#include "BTFuzzState.h"
#include "Util.h"
#include "Operation.h"
#include <fcntl.h>
#include <map>
#include <set>
#include <string>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


class BTFuzz {
  bool sema;
  u8* hci;
  u8* rt;
  static BTFuzz* bt;
  BTFuzzState init_state;
  BTFuzzState cur_state;
  std::string opStr;
  BTFuzz(){}

public:

  static BTFuzz* get(){
    if(!bt){ bt = new BTFuzz();}
    return bt;
  }

  void sync_hci();

  const char* get_op() {return opStr.c_str();}

  u32 serialize_state(u8*);

  void deserialize_state(u8*);

  // void sync_state();

  void restore_state();

  void enable_sema(bool s) { sema = s;}

  bool sema_enabled() { return sema;}

  void set_buffers(u8* _hci, u8* _rt) {hci=_hci; rt=_rt;}

  u32 fuzz_one(u8*);

  u32 fuzz_one_rand(u8*);

  u32 fuzz_one_sema(u8*);

  u32 fuzz_one_sema1(u8*);

  u32 fuzz_one_sema2(u8*);

  u32 fuzz_one_sema3(u8*);

  u32 fuzz_one_sema4(u8*);

  u32 fuzz_one_sema5(u8*);

  u32 handle_cmd(u8*, hci_command_t*);

  u32 handle_acl(u8*, hci_acl_t*);

  u32 handle_att(u8*, hci_acl_t*);

//   void handle_item(item_t*);

//   void handle_cmd(hci_command_t*);

//   void handle_evt(hci_event_t*);

//   void handle_op(operation_t*);

//   void handle_evt_con_complete(hci_event_t*);

//   void handle_evt_le_con_complete(hci_event_t*);

//   void handle_op_l2cap_register_service(operation_t*);

//   void handle_op_l2cap_create_channel(operation_t*);

};

#endif /* B143D1D5_36EB_4829_B56D_55AC37ABB19B */
