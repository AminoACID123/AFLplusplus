#ifndef ECBC282F_6C4B_4676_B798_A0938AE4B49D
#define ECBC282F_6C4B_4676_B798_A0938AE4B49D

#include "../../include/types.h"
#include <set>
#include <vector>

#define VTOR(x) v##x
#define SET(x) s##x

template<typename T>
void bytes2vec(std::vector<u8> vec, T data)
{
  u8* p = (u8*)&data; 
  for(;p-(u8*)&data<sizeof(T);p++)
    vec.push_back(*p);
}

template<typename T>
T set_at(std::set<T>& s, u32 i)
{
  auto iter = s.begin();
  while(i>0){ ++iter; --i;}
  return *iter;
}

void rand_init(s32);

u32 rand_below(u32 limit);

void rand_fill(u8* buf, u32 size);

#endif /* ECBC282F_6C4B_4676_B798_A0938AE4B49D */
