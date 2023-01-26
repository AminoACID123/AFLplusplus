#ifndef BC4227F0_1557_4970_B6D6_0412C93089D1
#define BC4227F0_1557_4970_B6D6_0412C93089D1

#include "../../include/types.h"
#include "../../include/bluetooth.h"

class Item {
protected:
    item_t* pItem;
public:
    Item() = default;
    Item(u8* buf) {pItem = (item_t*)buf;}
    u32 size() { return pItem->size; }
};

#endif /* BC4227F0_1557_4970_B6D6_0412C93089D1 */
