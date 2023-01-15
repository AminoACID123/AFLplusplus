#ifndef BT_MUTATE_H
#define BT_MUTATE_H

#include "assert.h"
#include "../../include/types.h"
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
#include <vector>


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

  struct hci_con{
    u8 valid;
    u16 handle;
    u8 type;
    u8 addr[6];
    hci_con(u8 t, u8* a)
    {
      type = t;
      memcpy(addr, a, 6);
    }
  }__attribute__((packed));

  u16 max_handle;
  // hci_con pending_le_con;
  // std::set<hci_con> pcon;
  // std::set<hci_con> con;
  // std::set<u16> cid;
  // std::set<u16> psm;
  // std::set<u16> pdiscon;
  // std::set<std::vector<u8>> pcmd;


  std::vector<hci_con> pcons;
  std::vector<hci_con> cons;
  std::vector<u16> pdiscon;
  std::vector<u16> cid;
  std::vector<u16> psm;
  std::vector<std::vector<u8>> pcmd;

public:

  BTFuzzState(){

  }

  inline std::vector<hci_con>& get_connections()
  {
    return cons;
  }

  inline hci_con& get_connection(u16 handle)
  {
    for(hci_con& c : cons){
      if(c.handle == handle)
        return c;
    }
    assert(false && "Connection not exist");
  }

  inline void add_pending_con(u8 type, u8* addr)
  {
    pcons.push_back(hci_con(type, addr));
  }

  inline void remove_pending_con(u8* addr)
  {
    for(auto it = pcons.begin(),eit=pcons.end();it!=eit;++it)
    {
      if(memcmp(addr, it->addr, 6) == 0)
        pcon.erase(it);
        return;
    }
  }

  inline void add_con(hci_con& c)
  {
    cons.push_back(c);
  }

  inline void remove_con(u16 handle)
  {
    for(auto it = cons.begin(),eit=cons.end();it!=eit;++it){
      if(it->handle == handle){
        con.erase(it);
        return;
      }
    }
  }

  inline void add_pending_discon(u16 handle)
  {
    for(auto it=pdiscon.begin(),eit=pdiscon.end();it!=eit;++it){
      if(*it == handle)
        return;
    }
    pdiscon.push_back(handle);
  }

  inline void remove_pending_discon(u16 handle)
  {
    for(auto it=pdiscon.begin(),eit=pdiscon.end();it!=eit;++it){
      if(*it == handle){
        pdiscon.erase(it);
        return;
      }
    }
  }

  static inline bool is_le(u8 addr_type)
  {
    return addr_type == BD_ADDR_TYPE_LE_RANDOM || addr_type == BD_ADDR_TYPE_LE_PUBLIC
        || addr_type == BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_PUBLIC
        || addr_type == BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_RANDOM;
  }

  inline void remove_pending_le_con()
  {
    for(auto it=pcons.begin(),eit=pcons.end();it!=eit;++it)
    {
      if(is_le(it->type)){
        pcon.erase(it);
        return;
      }
    }
  }
  inline void add_pending_cmd(hci_command_t* cmd)
  {
    pcmd.push_back(vector<u8>());
    pcmd.back().insert(pcmd.back().end(), (u8*)cmd, &cmd->param[cmd->len]);
  }

  inline void remove_pending_cmd(u32 i)
  {
    pcmd.erase(pcmd.begin() + i);
  }

  inline hci_command_t* get_pending_cmd(u32 i)
  {
    return (hci_command_t*)pcmd[i].data();
  }

  inline void add_psm(u16 _psm)
  {
    for(u16 p : psm)
      if(p == _psm) return;
    psm.push_back(_psm);
  }

  inline void add_cid(u16 _cid)
  {
    for(u16 c : cid)
      if(c == _cid) return;
    cid.push_back(_cid);
  }
};

#endif