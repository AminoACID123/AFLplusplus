#include "harness.h"
#include <map>
#include <stdint.h>
#include <vector>

struct item {
    uint32_t size;
    uint8_t flag;

};

struct hci {

};

struct test_case {
    uint32_t item_cnt;
    
}


class Item {
protected:
    char* data;
    std::vector<int> params;
    std::vector<std::vector<char>> param_data;
public:
    virtual char* serialize();
};

class HNS : public Item {
    int idx;
public: 
    char* serialize() {
        int size = 0;
        for(std::vector<char> param : param_data)
            size += (param.size() + 4);
        
    }
};

class HCI : public Item {
    uint16_t opcode;
public:
    char* serialize();
};

class TestCase {
    std::vector<Item*> items;
    char* databytes;
};