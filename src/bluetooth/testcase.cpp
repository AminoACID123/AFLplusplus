#include "../../include/config.h"
#include <map>
#include <stdbool.h>
#include <stdio.h>

std::map<int, bool> mutable_map;

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
        else if (flag == F_API)
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