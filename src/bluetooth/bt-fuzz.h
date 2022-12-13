#ifndef BT_MUTATE_H
#define BT_MUTATE_H

#include "../../include/types.h"

#include <fcntl.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


typedef u8 bd_addr_type_t;
typedef u16 hci_con_handle_t;

struct bd_addr_t {u8 bd_addr[6];};

#define ROTL(d, lrot) ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))))

class BTFuzzState {
  std::set<bd_addr_t> bd_addr_s;
  bd_addr_type_t bd_addr_type_s[6] = {0, 1, 2, 3, 4, 5};
  std::map<hci_con_handle_t, std::pair<bd_addr_t, bd_addr_type_t>>
      hci_con_handle_m;
  std::set<u16> l2cap_local_cid_s;
  std::set<u16> l2cap_remote_cid_s;
  std::set<u16> l2cap_local_psm_s;
  std::set<u16> l2cap_remote_psm_s;

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

  void reset() {
    bd_addr_s.clear();
    hci_con_handle_m.clear();
    l2cap_local_psm_s.clear();
    l2cap_remote_psm_s.clear();
    l2cap_local_cid_s.clear();
    l2cap_remote_cid_s.clear();
  }

  u32 core_parameter_choose(u8* buf, string name);

  u32 choose_bd_addr(u8* buf);

  u32 choose_bd_addr_type(u8* buf);

  u32 choose_hci_con_handle(u8* buf);

  u32 choose_l2cap_psm(u8* buf);

  u32 choose_l2cap_cid(u8* buf);

  void generate_gap_connect();

  void generate_hci_con_complete_event();

  void generate_hci_le_con_complete_event();

  void generate_gap_disconnect();

  void generate_l2cap_create_channel();

  void generate_l2cap_register_service();

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