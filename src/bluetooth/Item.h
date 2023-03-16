#ifndef BLUETOOTH_ITEM_H
#define BLUETOOTH_ITEM_H

#include "../../include/types.h"
#include "../../include/bluetooth.h"

class Item {
protected:
    item_t* pItem;
public:
    Item() = default;
    Item(u8* buf) { pItem = (item_t*)buf; }
    u32 size() { return pItem->size; }
};

#endif
