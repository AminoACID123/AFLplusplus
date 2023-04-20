#ifndef BLUETOOTH_BTFUZZ_H
#define BLUETOOTH_BTFUZZ_H


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
public:

  static BTFuzz* get(){
    if(!bt){ bt = new BTFuzz();}
    return bt;
  }

  void sync_hci();

  const char* getOpStr() 
  {
    return opStr.c_str();
  }

  u32 serializeState(u8*);

  void deserializeState(u8*);

  void restoreState();

  void setSema(bool s) 
  { 
    sema = s;
  }

  bool getSema() 
  { 
    return sema;
  }

  void setRuntime(u8* _hci, u8* _rt) 
  {
    hci=_hci; 
    rt=_rt;
  }

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

private:
  bool sema;
  u8* hci;
  u8* rt;
  static BTFuzz* bt;
  BTFuzzState initState;
  BTFuzzState curState;
  std::string opStr;
  BTFuzz(){}
};

#endif
