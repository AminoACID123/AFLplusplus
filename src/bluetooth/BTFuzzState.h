#ifndef BT_MUTATE_H
#define BT_MUTATE_H

#include "../../include/types.h"
#include "BTFuzz.h"
#include "Hci.h"
#include "Operation.h"
#include "Util.h"
#include "assert.h"
#include <fcntl.h>
#include <map>
#include <set>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

extern std::vector<u16> psm_fixed;
extern std::vector<u16> cid_fixed;

class BTFuzzState {

  // struct bd_addr{
  //   u8 addr[6];
  //   bool operator < (const bd_addr& other) const{
  //     for(u32 i=0;i<6;i++)
  //       if(addr[i] < other.addr[i])
  //         return true;
  //     return false;
  //   }
  // }__attribute__((packed));

  friend class BTFuzz;

  struct hci_con {
    u16 handle;
    u8 type;
    u8 addr[6];
    hci_con() {}
    hci_con(u8 t, u8 *a) {
      type = t;
      memcpy(addr, a, 6);
    }
       template<typename Archive>
    Archive& serialize(Archive& ar)
    {
      ar & handle;
      ar & type;
      ar & addr;
      return ar;
    }
  };


  // hci_con pending_le_con;
  // std::set<hci_con> pcon;
  // std::set<hci_con> con;
  // std::set<u16> cid;
  // std::set<u16> psm;
  // std::set<u16> pdiscon;
  // std::set<std::vector<u8>> pcmd;
  u16 max_handle;
  std::vector<hci_con> pcon;
  std::vector<hci_con> con;
  std::vector<u16> pdiscon;
  std::vector<u16> cid;
  std::vector<u16> psm;
  std::vector<std::vector<u8>> pcmd;

public:
  BTFuzzState() {}

   template<typename Archive>
    Archive& serialize(Archive& ar)
    {
      ar & max_handle;
      ar & pcon;
      ar & con;
      ar & pdiscon;
      ar & cid;
      ar & psm;
      ar & pcmd;
      return ar;
    }
  
  inline void remove_pcmd(u32 i){
    pcmd.erase(pcmd.begin() + i);
  }

  inline void add_pcmd(item_t* item){
    pcmd.push_back(std::vector<u8>());
    pcmd.back().assign(item->data, &item->data[item->size]);
  }
  
  inline bool choose_con_handle(u16* out, u8 type){
    if(con.empty())
      return false;
    if(type == DUAL){
      u32 i = rand_below(con.size());
      *out = con[i].handle;
      return true;  
    }else{
      std::vector<hci_con> temp;
      for(hci_con& c : con){
        if((is_le(c.type) && type == LE) || (!is_le(c.type) && type == CLASSIC))
          temp.push_back(c);
      }
      if(temp.empty())
        return false;
      u32 i = rand_below(temp.size());
      *out = temp[i].handle;
      return true;
    }
  }

  inline bool choose_cid(u16* out){
    if(cid.empty())
      return false;
    *out = cid[rand_below(cid.size())];
    return true;
  }

  inline bool choose_psm(u16* out){
    if(psm.empty())
      return false;
    *out = psm[rand_below(psm.size())];
    return true;
  }

  inline void reset()
  {
    max_handle = 0;
    pcon.clear();
    con.clear();
    pdiscon.clear();
    cid.assign(cid_fixed.begin(), cid_fixed.end());
    psm.assign(psm_fixed.begin(), psm_fixed.end());
    pcmd.clear();
  }

  inline hci_con &get_connection(u16 handle) {
    for (hci_con &c : con) {
      if (c.handle == handle)
        return c;
    }
    assert(false && "Connection not exist");
  }

  inline bool has_connection(u16 handle) {
    for(hci_con& c : con)
      if(c.handle == handle)
        return true;
    return false;
  }

  inline void add_pending_con(u8 type, u8 *addr) {
    pcon.push_back(hci_con(type, addr));
  }

  inline void remove_pending_con(u8 *addr) {
    for (auto it = pcon.begin(), eit = pcon.end(); it != eit; ++it) {
      if (memcmp(addr, it->addr, 6) == 0)
        pcon.erase(it);
      return;
    }
  }

  inline void add_con(hci_con &c) { 
    // Parameter* _handle = get_parameter(CORE_PARAMETER_HCI_HANDLE);
    // _handle->domain.push_back(std::vector<u8>());
    // bytes2vec(_handle->domain.back(), c.handle);
    con.push_back(c);
  }

  inline void remove_con(u16 handle) {
    for (auto it = con.begin(), eit = con.end(); it != eit; ++it) {
      if (it->handle == handle) {
        con.erase(it);
        // Parameter* pHandle = get_parameter(CORE_PARAMETER_HCI_HANDLE);
        // for(auto it=pHandle->domain.begin(),eit=pHandle->domain.end();it!=eit;++it)
        // {
        //    u16 h = (*it)[0] | ((*it)[1] << 8);
        //    if(h == handle){
        //     pHandle->domain.erase(it);
        //     return;
        //    }
        // }
        return;
      }
    }
  }

  inline void add_pending_discon(u16 handle) {
    for (auto it = pdiscon.begin(), eit = pdiscon.end(); it != eit; ++it) {
      if (*it == handle)
        return;
    }
    pdiscon.push_back(handle);
  }

  inline void remove_pending_discon(u16 handle) {
    for (auto it = pdiscon.begin(), eit = pdiscon.end(); it != eit; ++it) {
      if (*it == handle) {
        pdiscon.erase(it);
        return;
      }
    }
  }

  static inline bool is_le(u8 addr_type) {
    return addr_type == BD_ADDR_TYPE_LE_RANDOM ||
           addr_type == BD_ADDR_TYPE_LE_PUBLIC ||
           addr_type == BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_PUBLIC ||
           addr_type == BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_RANDOM;
  }

  inline void remove_pending_le_con() {
    for (auto it = pcon.begin(), eit = pcon.end(); it != eit; ++it) {
      if (is_le(it->type)) {
        pcon.erase(it);
        return;
      }
    }
  }
  inline void add_pending_cmd(hci_command_t *cmd) {
    pcmd.push_back(std::vector<u8>());
    pcmd.back().assign((u8 *)cmd, &cmd->param[cmd->len]);
  }

  inline void remove_pending_cmd(u32 i) { pcmd.erase(pcmd.begin() + i); }

  inline hci_command_t *get_pending_cmd(u32 i) {
    return (hci_command_t *)pcmd[i].data();
  }

  inline void add_psm(u16 _psm) {
    for (u16 p : psm)
      if (p == _psm)
        return;
    psm.push_back(_psm);
    // Parameter* pPsm = get_parameter(CORE_PARAMETER_PSM);
    // pPsm->domain.push_back(std::vector<u8>());
    // bytes2vec(pPsm->domain.back(), _psm);
  }

  inline void add_cid(u16 _cid) {
    for (u16 c : cid)
      if (c == _cid)
        return;
    cid.push_back(_cid);
    // Parameter* pCid = get_parameter(CORE_PARAMETER_CID);
    // pCid->domain.push_back(std::vector<u8>());
    // bytes2vec(pCid->domain.back(), _cid);
  }
};

#endif