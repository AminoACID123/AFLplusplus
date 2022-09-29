#ifndef HCI_GRAPH_H
#define HCI_GRAPH_H

#include "hci.h"
#include <map>
#include <stdint.h>
#include <string>

#define RP_COMPLETE 0
#define RP_STATUS   1
#define RP_NONE     2

struct HCINode {
  uint16_t opcode;
  std::string name;
  uint8_t reply;
  HCINode(uint16_t _opcode, std::string _name, uint8_t _reply):
    opcode(_opcode), name(_name), reply(_reply){}
};

uint8_t get_reply(uint16_t opcode);

#endif