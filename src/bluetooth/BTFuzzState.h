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

typedef u8 bd_addr_type_t;
typedef u16 hci_con_handle_t;

struct bd_addr_t {u8 bd_addr[6];};

#define ROTL(d, lrot) ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))))

#define L2CAP_CID_SIGNALING                        0x0001
#define L2CAP_CID_CONNECTIONLESS_CHANNEL           0x0002
#define L2CAP_CID_ATTRIBUTE_PROTOCOL               0x0004
#define L2CAP_CID_SIGNALING_LE                     0x0005
#define L2CAP_CID_SECURITY_MANAGER_PROTOCOL        0x0006
#define L2CAP_CID_BR_EDR_SECURITY_MANAGER          0x0007
#define FIXED_CID(cid) (cid >= L2CAP_CID_SIGNALING && cid <= L@L2CAP_CID_BR_EDR_SECURITY_MANAGER)

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


class BTFuzzState {
  std::map<hci_con_handle_t, std::pair<bd_addr_t, bd_addr_type_t>>
      con_s;
  std::set<u16> cid_s;
  std::set<u16> psm_s;

  s32 dev_urandom_fd;
  u64 rand_seed[3];
  u32 rand_cnt;

  static BTFuzzState* bt;

  // BTFuzzState() {
  //   dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  //   read(dev_urandom_fd, &rand_seed, sizeof(rand_seed));
  // }
  BTFuzzState();

  bool connected(bd_addr_t& addr){
    for(auto con : hci_con_handle_m){
      if(memcmp(con.second.first.bd_addr, addr.bd_addr, CORE_PARAMETER_BD_ADDR_SIZE)==0)
        return true;
    }
    return false;
  }

public:
  static BTFuzzState* get(){
    if(!bt) bt = new BTFuzzState();
    return bt;
  }

  void reset();

  Parameter* generate_core_parameter(Parameter*);

  Parameter* generate_bd_addr();

  Parameter* generate_bd_addr_type();

  Parameter* generate_hci_con_handle();

  Parameter* generate_l2cap_psm();

  Parameter* generate_l2cap_cid();

  Operation* generate_gap_connect();

  Operation* generate_gap_connect_cancel();

  Operation* generate_hci_con_complete_event();

  Operation* generate_hci_le_con_complete_event();

  Operation* generate_gap_disconnect();

  Operation* generate_l2cap_create_channel();

  Operation* generate_l2cap_register_service();

  Operation* generate_random_operation(u32, bool);

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

  void rand_fill(u8* buf, u32 size){
    for(u32 i=0;i<size/sizeof(u32);i++)
      *((u32*)buf + i) = rand_below(UINT32_MAX);
    for(u32 i=0;i<size%sizeof(u32);i++)
      buf[size - i - 1] = rand_below(UINT8_MAX);
  }
};

#endif