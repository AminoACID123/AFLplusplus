#ifndef BT_MUTATE_H
#define BT_MUTATE_H

#include "../../include/types.h"

#include <fcntl.h>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef u8 bd_addr_type_t;
typedef u16 hci_con_handle_t;

struct bd_addr_t {u8 bd_addr[6];};

#define ROTL(d, lrot) ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))))

#define CORE_OPERATION_NUM 4
#define CORE_PARAMETER_NUM 5

#define OPSIZE(nr) sizeof(operation_header) + nr * sizeof(parameter_header) -sizeof(u32) 

#define CORE_PARAMETER_BD_ADDR                  "bd_addr_t"
#define CORE_PARAMETER_BD_ADDR_SIZE             6
#define CORE_PARAMETER_HCI_HANDLE               "hci_con_handle_t"
#define CORE_PARAMETER_HCI_HANDLE_SIZE          2
#define CORE_PARAMETER_BD_ADDR_TYPE             "bd_addr_type_t"
#define CORE_PARAMETER_BD_ADDR_TYPE_SIZE        1
#define CORE_PARAMETER_CID                      "cid"
#define CORE_PARAMETER_CID_SIZE                 2
#define CORE_PARAMETER_PSM                      "psm"
#define CORE_PARAMETER_PSM_SIZE                 2

#define CORE_OPERATION_GAP_CONNECT                    "gap_connect"           // bd_addr_t, bd_addr_type_t
#define CORE_OPERATION_GAP_CONNECT_SIZE               OPSIZE(2) + CORE_PARAMETER_BD_ADDR_SIZE + CORE_PARAMETER_BD_ADDR_TYPE_SIZE
#define CORE_OPERATION_GAP_CONNECT_CANCEL             "gap_connect_cancel"
#define CORE_OPERATION_GAP_CONNECT_CANCEL_SIZE        OPSIZE(0)
#define CORE_OPERATION_GAP_DISCONNECT                 "gap_disconnect"       // hci_con_handle_t
#define CORE_OPERATION_GAP_DISCONENCT_SIZE            OPSIZE(1) + CORE_PARAMETER_HCI_HANDLE_SIZE
#define CORE_OPERATION_L2CAP_CREATE_CHANNEL           "l2cap_create_channel"     // bd_addr, psm
#define CORE_OPERATION_L2CAP_CREATE_CHANNEL_SIZE      OPSIZE(2) + CORE_PARAMETER_BD_ADDR_SIZE + CORE_PARAMETER_PSM_SIZE
#define CORE_OPERATION_L2CAP_REGISTER_SERVICE         "l2cap_register_service"     //psm
#define CORE_OPERATION_L2CAP_REGISTER_SERVICE_SIZE    OPSIZE(1) + CORE_PARAMETER_PSM_SIZE


#define L2CAP_CID_SIGNALING                        0x0001
#define L2CAP_CID_CONNECTIONLESS_CHANNEL           0x0002
#define L2CAP_CID_ATTRIBUTE_PROTOCOL               0x0004
#define L2CAP_CID_SIGNALING_LE                     0x0005
#define L2CAP_CID_SECURITY_MANAGER_PROTOCOL        0x0006
#define L2CAP_CID_BR_EDR_SECURITY_MANAGER          0x0007

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

extern std::string core_parameters[CORE_PARAMETER_NUM];
extern std::string core_operations[CORE_OPERATION_NUM];

class BTFuzzState {
  std::set<bd_addr_t> bd_addr_s;
  bd_addr_type_t bd_addr_type_s[6] = {0, 1, 2, 3, 4, 5};
  std::map<hci_con_handle_t, std::pair<bd_addr_t, bd_addr_type_t>>
      hci_con_handle_m;
  std::set<u16> cid_s;
  std::set<u16> psm_s;

  s32 dev_urandom_fd;
  u64 rand_seed[3];
  u32 rand_cnt;

  static BTFuzzState* bt;

  BTFuzzState() {
    dev_urandom_fd = open("/dev/urandom", O_RDONLY);
    read(dev_urandom_fd, &rand_seed, sizeof(rand_seed));
  }

public:
  static BTFuzzState* get(){
    if(!bt) bt = new BTFuzzState();
    return bt;
  }

  void reset();

  u32 core_parameter_choose(u8* buf, std::string name);

  u32 choose_bd_addr(u8* buf);

  u32 choose_bd_addr_type(u8* buf);

  u32 choose_hci_con_handle(u8* buf);

  u32 choose_l2cap_psm(u8* buf);

  u32 choose_l2cap_cid(u8* buf);

  u32 generate_gap_connect(u8* buf);

  u32 generate_gap_connect_cancel(u8* buf);

  u32 generate_hci_con_complete_event(u8* buf);

  u32 generate_hci_le_con_complete_event(u8* buf);

  u32 generate_gap_disconnect(u8* buf);

  u32 generate_l2cap_create_channel(u8* buf);

  u32 generate_l2cap_register_service(u8* buf);

  u64 rand_next() {
    u64 xp = rand_seed[0];
    rand_seed[0] = 15241094284759029579u * rand_seed[1];
    rand_seed[1] = rand_seed[1] - xp;
    rand_seed[1] = ROTL(rand_seed[1], 27);
    return xp;
  }

  u32 rand_below(u32 limit) {
    if (limit <= 1)
      return 0;
    if (unlikely(!rand_cnt--)) {
      read(dev_urandom_fd, &rand_seed, sizeof(rand_seed));
      rand_cnt = (100000 / 2) + (rand_seed[1] % 100000);
    }

    u64 unbiased_rnd;
    do {
      unbiased_rnd = rand_next();
    } while (unlikely(unbiased_rnd >= (UINT64_MAX - (UINT64_MAX % limit))));
    return unbiased_rnd % limit;
  }
};

#endif