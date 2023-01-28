#include "../../include/bluetooth.h"
#include "../../include/types.h"
#include "Operation.h"
#include <iostream>
#include <stdio.h>
using namespace std;

void hex_dump(u8* buf, u32 size){
    for(u32 i=0;i<size;i++){
        printf("%02x ", buf[i]);
    }
}

int main(int argc, char** argv){
    if(argc != 2){
        cout << "Input file name." << endl;
        return 0;
    }

    item_t* pItem;
    FILE* f = fopen(argv[1], "rb");
    static u8 buf[BT_MAX_BUFFER_SIZE];
    size_t n = fread(buf, 1, BT_MAX_BUFFER_SIZE, f);
    BT_ItemForEach3(pItem, buf, n){
        if(pItem->data[0] == OPERATION){
            operation_t* pOp = (operation_t*)pItem->data;
            parameter_t* param = (parameter_t*)pOp->data;
            printf("Operation: %d\n", pOp->id);
            for(u32 i=0;i<pOp->params;i++){
                printf("\tParameter %d: ", i);
                hex_dump(param->data, param->len);
                printf("\n");
                param = (parameter_t*)&param->data[param->len];
            }
        }else if(pItem->data[0] == HCI_EVENT_PACKET){
            hci_event_t* pEvt = (hci_event_t*)pItem->data;
            printf("Event: %02x\n", pEvt->opcode);
            printf("\t");
            hex_dump(pEvt->param, pEvt->len);
            printf("\n");
        }
    }
    return 0;
}