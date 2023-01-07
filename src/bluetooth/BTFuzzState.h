#ifndef BT_MUTATE_H
#define BT_MUTATE_H

#include "../../include/types.h"
#include "Operation.h"
#include <fcntl.h>
#include <map>
#include <set>
#include <string>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define L2CAP_CID_SIGNALING                        0x0001
#define L2CAP_CID_CONNECTIONLESS_CHANNEL           0x0002
#define L2CAP_CID_ATTRIBUTE_PROTOCOL               0x0004
#define L2CAP_CID_SIGNALING_LE                     0x0005
#define L2CAP_CID_SECURITY_MANAGER_PROTOCOL        0x0006
#define L2CAP_CID_BR_EDR_SECURITY_MANAGER          0x0007
#define FIXED_CID(cid) (cid >= L2CAP_CID_SIGNALING && cid <= L2CAP_CID_BR_EDR_SECURITY_MANAGER)

#define BLUETOOTH_PSM_SDP                                                                0x0001
#define BLUETOOTH_PSM_RFCOMM                                                             0x0003
#define BLUETOOTH_PSM_TCS_BIN                                                            0x0005
#define BLUETOOTH_PSM_TCS_BIN_CORDLESS                                                   0x0007
#define BLUETOOTH_PSM_BNEP                                                               0x000F
#define BLUETOOTH_PSM_HID_CONTROL                                                        0x0011
#define BLUETOOTH_PSM_HID_INTERRUPT                                                      0x0013
#define BLUETOOTH_PSM_UPNP                                                               0x0015
#define BLUETOOTH_PSM_AVCTP                                                              0x0017
#define BLUETOOTH_PSM_AVDTP                                                              0x0019
#define BLUETOOTH_PSM_AVCTP_BROWSING                                                     0x001B
#define BLUETOOTH_PSM_UDI_C_PLANE                                                        0x001D
#define BLUETOOTH_PSM_ATT                                                                0x001F
#define BLUETOOTH_PSM_3DSP                                                               0x0021
#define BLUETOOTH_PSM_LE_PSM_IPSP                                                        0x0023
#define BLUETOOTH_PSM_OTS                                                                0x0025
#define FIXED_PSM(psm) ((psm % 2 == 1) && ((psm <= BLUETOOTH_PSM_TCS_BIN_CORDLESS) || (psm >= BLUETOOTH_PSM_BNEP && psm <= BLUETOOTH_PSM_OTS)))

#define Classic 0
#define LE 1

class BTFuzzState {

  struct bd_addr{
    u8 addr[6];
    bool operator < (const bd_addr& other) const{
      for(u32 i=0;i<6;i++)
        if(addr[i] < other.addr[i])
          return true;
      return false;
    }
  }__attribute__((packed));

  struct hci_con{
    u16 handle;
    u8 type;
    bd_addr addr;
    bool operator < (const hci_con& other) const{
      if(handle < other.handle)
        return true;
      if(type < other.type)
        return type;
      return memcmp(addr.addr, other.addr.addr, 6) < 0;
    }
  }__attribute__((packed));


  u16 max_handle;

  std::set<hci_con> sCon;
  std::vector<hci_con> vCon;

  std::set<u16> sCid;
  std::vector<u16> vCid;

  std::set<u16> sPsm;
  std::vector<u16> vPsm;

  hci_con pending_le_con;

  std::set<hci_con> sPending_con;
  std::vector<hci_con> vPending_con;

  std::set<u16> sPending_discon;

  std::vector<std::vector<u8>> vPending_cmd;
  std::set<std::vector<u8>> sPending_cmd;

  bool sema;

  u8* hci;
  u8* rt;

  static BTFuzzState* bt;

  BTFuzzState();

  void update();

public:
  static BTFuzzState* get(){
    if(!bt){ bt = new BTFuzzState();}
    return bt;
  }

  u32 serialize(u8*);

  void deserialize(u8*);

  void reset();

  void sync();

  void enable_sema(bool s) { sema = s;}

  void set_buffers(u8* _hci, u8* _rt) {hci=_hci; rt=_rt;}

  u32 step_one(u8*, u32);

  u32 fuzz_one(u8*);

  void handle_item(item_t*);

  void handle_cmd(hci_command_t*);

  void handle_evt(hci_event_t*);

  void handle_op(operation_t*);

  void handle_evt_con_complete(hci_event_t*);

  void handle_evt_le_con_complete(hci_event_t*);

  void handle_op_l2cap_register_service(operation_t*);

  void handle_op_l2cap_create_channel(operation_t*);

};

#endif