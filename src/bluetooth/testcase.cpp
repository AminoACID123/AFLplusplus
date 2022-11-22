#include "../../include/config.h"
#include "harness.h"
#include <map>
#include <stdbool.h>
#include <stdio.h>
#include <vector>

std::map<int, bool> mutable_map;
std::vector<int, int> mutable_vec;

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

void init_mutable_map(char *buf, int len)
{
    mutable_map.clear();
    int i;
    for (i = 0; i < len; i++)
        mutable_map[i] = false;
    i = 0;
    while (i < len)
    {
        int size = *(int *)(buf + i);
        char flag = buf[i + 4];
        for (int j = i; j < i + 5; j++)
            mutable_map[j] = false;
        if (flag == HCI_EVENT_PACKET)
        {
            for (int j = i + 7; j < i + size; j++)
                mutable_map[j] = true;
        }
        else if (flag == OPERATION)
        {
            int j = i + 13;
            int arg_in_cnt = *(int *)(buf + i + 9);
            for (int k = 0; k < arg_in_cnt; k++)
            {
                int arg_len = *(int *)(buf + j + 4);
                for (int n = j + 8; n < j + 8 + arg_len; n++)
                    mutable_map[n] = true;
                j += (8 + arg_len);
            }
        }
        i += (4 + size);
    }
}

bool can_mutate( int i)
{
    return mutable_map[i];
}

int get_data_param_len(char *buf, int len)
{
    int i = 0;
    int ret = 0;
    while (i < len)
    {
        int size = *(int *)(buf + i);
        char flag = buf[i + 4];

        if (flag == HCI_EVENT_PACKET)
        {
            for (int j = i + 7; j < i + size; j++)
                ret++;
        }
        else if (flag == OPERATION)
        {
            int j = i + 13;
            int arg_in_cnt = *(int *)(buf + i + 9);
            for (int k = 0; k < arg_in_cnt; k++)
            {
                int arg_len = *(int *)(buf + j + 4);
                for (int n = j + 8; n < j + 8 + arg_len; n++)
                    ret++;
                j += (8 + arg_len);
            }
        }
        i += (4 + size);
    }
    return ret;
}

void bt_mutate_data_flipbit(char* buf, int len, int pos) 
{
    
}

void bt_mutate_data_interesting8(char* buf, int len, uint32_t rand)
{

}

void bt_mutate_data_interesting16(char* buf, int len, uint32_t rand) 
{

}

void bt_mutate_data_interesting32(char* buf, int len, uint32_t rand)
{

}

void bt_mutate_parameter(char* buf, int len, uint32_t rand)
{

}



void bt_mutate

/*
bool mutate(char *buf, int pos)
{
}

int *get_size(char *buf, int pos)
{
}

bool expand(char *buf, int *len)
{
}
*/

int main(){
    
    char buf[2048];
    FILE* f =fopen("/home/xaz/Documents/AFLplusplus/testcases/bluetooth/btstack/in/1","r");
    int len = fread(buf, 1, 2048, f);
    init_mutable_map(buf, len);
    for(auto item : mutable_map){
        printf("%d: %s\n",item.first, item.second ? "true" : "false");
    }
    return 0;
}