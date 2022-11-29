#include <string.h>
#include "afl-fuzz.h"
#include "bluetooth.h"
#include "bluetooth_api.h"

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

typedef void (*bt_mutator)(afl_state_t *, u8 *, u32);

static inline u32 get_num_item(u8 *buf, u32 len) {
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    int size = *(int *)(buf + i);
    cnt++;
    i += (4 + size);
  }
  return cnt;
}

static inline u32 get_num_operation(u8 *buf, u32 len) {
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];
    if (flag == OPERATION) { cnt++; }
    i += (4 + size);
  }
  return cnt;
}

static inline u32 get_num_hci(u8 *buf, u32 len) {
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];
    if (flag == HCI_EVENT_PACKET) { cnt++; }
    i += (4 + size);
  }
  return cnt;
}

static inline bool has_conn_complete(u8 *buf, u32 len) {
  u32 i = 0;
  while (i < len) {
    u32 size = *(int *)(buf + i);
    u8  flag = buf[i + 4];
    if (flag == HCI_EVENT_PACKET && buf[i + 5] == 3) { return true; }
    i += (4 + size);
  }
  return false;
}

int get_parameter_num(u8 *buf, u32 len) {
  u32 i = 0;
  u32 ret = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];

    if (flag == HCI_EVENT_PACKET) {
      ret++;
    } else if (flag == OPERATION) {
      int j = i + 13;
      int arg_in_cnt = *(int *)(buf + i + 9);
      int arg_len = *(int *)(buf + j + 4);
      for (int k = 0; k < arg_in_cnt; k++) {
        ret++;
        j += (8 + arg_len);
      }
    }
    i += (4 + size);
  }
  return ret;
}

void bt_mutator_flip_bit(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT1");
  strcat(afl->mutation, afl->m_tmp);
#endif
  FLIP_BIT(buf, rand_below(afl, len << 3));
}

void bt_mutator_interesting8(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)] =
      interesting_8[rand_below(afl, sizeof(interesting_8))];
}

void bt_mutator_interesting16_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16LE");
  strcat(afl->mutation, afl->m_tmp);
#endif
  *(u16 *)(buf + rand_below(afl, len - 1)) =
      interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];
}

void bt_mutator_interesting16_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE");
  strcat(afl->mutation, afl->m_tmp);
#endif
  *(u16 *)(buf + rand_below(afl, len - 1)) =
      SWAP16(interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);
}

void bt_mutator_interesting32_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 4) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32LE");
  strcat(afl->mutation, afl->m_tmp);
#endif
  *(u32 *)(buf + rand_below(afl, len - 3)) =
      interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];
}

void bt_mutator_interesting32_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 4) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE");
  strcat(afl->mutation, afl->m_tmp);
#endif
  *(u32 *)(buf + rand_below(afl, len - 3)) =
      SWAP32(interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);
}

void bt_mutator_subtract8(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8-");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)] -= 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_add8(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8+");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)] += 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_subtract16_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16LE-");
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 1);
  *(u16 *)(buf + pos) -= 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_subtract16_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE-");
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 1);
  u16 num = 1 + rand_below(afl, ARITH_MAX);
  *(u16 *)(buf + pos) = SWAP16(SWAP16(*(u16 *)(buf + pos)) - num);
}

void bt_mutator_add16_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16LE+");
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 1);
  *(u16 *)(buf + pos) += 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_add16_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+BE-%u_%u", pos, num);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 1);
  u16 num = 1 + rand_below(afl, ARITH_MAX);
  *(u16 *)(buf + pos) = SWAP16(SWAP16(*(u16 *)(buf + pos)) + num);
}

void bt_mutator_subtract32_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 4) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_-%u", pos);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 3);
  *(u32 *)(buf + pos) -= 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_subtract32_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 4) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_BE-%u-%u", pos, num);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 3);
  u32 num = 1 + rand_below(afl, ARITH_MAX);

  *(u32 *)(buf + pos) = SWAP32(SWAP32(*(u32 *)(buf + pos)) - num);
}

void bt_mutator_add32_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 4) return;

  u32 pos = rand_below(afl, len - 3);

#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+-%u", pos);
  strcat(afl->mutation, afl->m_tmp);
#endif
  *(u32 *)(buf + pos) += 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_add32_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 4) return;

  u32 pos = rand_below(afl, len - 3);
  u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+BE-%u-%u", pos, num);
  strcat(afl->mutation, afl->m_tmp);
#endif
  *(u32 *)(buf + pos) = SWAP32(SWAP32(*(u32 *)(buf + pos)) + num);
}

void bt_mutator_random8(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)] ^= 1 + rand_below(afl, 255);
}

void bt_mutator_increase_byte(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)]++;
}

void bt_mutator_decrease_byte(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)]--;
}

void bt_mutator_flip_byte(afl_state_t *afl, u8 *buf, u32 len) {
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
  strcat(afl->mutation, afl->m_tmp);
#endif
  buf[rand_below(afl, len)] ^= 0xff;
}

void mutate_parameter(afl_state_t *afl, u8 *buf, u32 len, bt_mutator mutator) {
  u32 param = rand_below(afl, get_parameter_num(buf, len));
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    item_hdr_t *item = (item_hdr_t *)(buf + i);
    if (item->flag == HCI_EVENT_PACKET) {
      if (cnt == param) {
        hci_evt_hdr_t* evt = (hci_evt_hdr_t*)item->payload;
        mutator(afl, &evt->param_len, BT_MAX_HCI_EVT_SIZE + 1);
        return;
      }
      cnt++;
    } else if (item->flag == OPERATION) {
      u32 j = 0;
      operation_hdr_t* op = (operation_hdr_t*)item->payload;
      for (int k = 0; k < op->param_cnt; k++) {
        parameter_t* param = (parameter_t*)(op->param + j);
        if (cnt == param) {
          mutator(afl, param->data, param->param_len);
          return;
        }
        cnt++;
        j += (sizeof(parameter_t) + param->param_len);
      }
    }
    i += (sizeof(item->size) + item->size);
  }
}

// extern void generate_random_harness(u32 idx, u32 seed, u8 *out_buf);

void bt_mutator_insert_operation(afl_state_t *afl, u8 **buf, u32 *len) {
  u32 n = get_num_operation(*buf, *len);
  u32 pos = rand_below(afl, n);
  u32 idx = rand_below(afl, get_total_operation());
  u32 seed = rand_below(afl, UINT32_MAX);
  u8  temp_buf[BT_MAX_BUFFER_SIZE];
  item_hdr_t* item = (item_hdr_t*)temp_buf;
  u32 insert_len;
  u32 insert_to = 0;

  generate_random_operation(idx, seed, temp_buf);
  insert_len = item->size + sizeof(item->size);
  if(*len + insert_len > MAX_FILE) return;

  u32 i = 0;
  u32 cnt = 0;
  while (i < *len) {
    item = (item_hdr_t*)(*buf + i);
    if (item->flag == OPERATION) {
      if (cnt == pos) {
        insert_to = i;
        break;
      }
      cnt++;
    }
    i += (item->size + sizeof(item->size));
  }

#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s-%u-%u", "insert",
           clone_to, clone_len);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), *len + insert_len);
  if (unlikely(!new_buf)) { PFATAL("alloc"); }

  /* Head */

  memcpy(new_buf, *buf, insert_to);

  /* Inserted part */

  memcpy(new_buf + insert_to, temp_buf, insert_len);

  /* Tail */
  memcpy(new_buf + insert_to + insert_len, *buf + insert_to, *len - insert_to);

  *buf = new_buf;
  afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
  *len += insert_len;
}

void bt_mutator_delete_operation(afl_state_t *afl, u8 *buf, u32 *len) {
  u32 n;
  u32 to_delete, delete_len, delete_pos;
  u32 i, cnt;
  item_hdr_t* item;

  n = get_num_operation(buf, *len);
  if (n == 1) return;
  to_delete = rand_below(afl, n);
  delete_len = 0;
  delete_pos = 0;

  while (i < *len) {
    item = (item_hdr_t*)(buf + i);
    if (item->flag == OPERATION) {
      if (cnt == to_delete) {
        delete_pos = i;
        delete_len = item->size + sizeof(item->size);
        break;
      }
      cnt++;
    }
    i += (item->size + sizeof(item->size));
  }

  memmove(buf, buf + delete_pos + delete_len, *len - delete_pos - delete_len);
  *len -= delete_len;
}

// u8 bt_mutator_expand_one(afl_state_t *afl, u8 **buf, u32 *len, u32 cmd)
// {
//   u32 i = 0;
//   u32 pos = 0;
//   u32 item = 0;
//   u32 size = 0;
//   u8* hci_log = afl->fsrv.trace_bits2;

//   while (size = *(u32 *)(hci_log + i)) {
//     u8 flag = *(hci_log + i + 4);
//     if(flag == HCI_COMMAND_DATA_PACKET){
//       if(pos == cmd){
//         u16 opcode = *(u16*)(hci_log + i + 5);
//         u8 temp_buf[BT_MAX_HCI_EVT_SIZE + 4 + 1 + 2];
//         *(int *)temp_buf = BT_MAX_HCI_EVT_SIZE + 2 + 1;
//         temp_buf[4] = HCI_EVENT_PACKET;
//         struct hci_event_header *hdr = &temp_buf[5];
//         hdr->parameter_len = 0xff; 
//         if(reply_with_complete(opcode)){
//           hdr->opcode = HCI_EVENT_COMMAND_COMPLETE;
//           struct hci_event_command_complete *evt = hdr->paramters;
//           evt->command_opcode = opcode;
//           evt->num_hci_command_packets = 1;
//           evt->return_parameters[0] = 0;
//           bt_mutator_insert_hci_at(afl, buf, len, pos, temp_buf, sizeof(temp_buf));
//         }else if (reply_with_status(opcode)){
//           hdr->opcode = HCI_EVENT_COMMAND_STATUS;
//           struct hci_event_command_status *evt = hdr->paramters;
//           evt->command_opcode = opcode;
//           evt->status = 0;
//           evt->num_hci_command_packets = 1;
//         }
//       }
//       pos++;
//     }
//     else if (flag == OPERATION || flag == HCI_EVENT_PACKET) {
//       item++;
//     }
//     i += (4 + size);
//   }
//   return 0;
// }

/* Expand a harness seq */
// u8 bt_mutator_expand(afl_state_t *afl, u8 **buf, u32 *len) {
//   u8 fault = 0;
//   u32 cmd;
//   while (true) {
//     if(fault = common_fuzz_stuff(afl, *buf, *len)) return fault;
//     if(!bt_mutator_expand_one(afl, buf, len, cmd)) break;
//     cmd++;
//   }
// }

void bt_mutator_insert_item(afl_state_t *afl, u8 **buf, u32 *len, u32 pos,
                              u8 *insert_buf, u32 insert_len) {
  u32 insert_to = 0;
  u32 i = 0;
  u32 cnt = 0;
  item_hdr_t* item;

  while (i < *len) {
    item = (item_hdr_t*)(*buf + i);
    if (cnt == pos) {
      insert_to = i;
      break;
    }
    cnt++;
    i += (item->size + sizeof(item->size));
  }

#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s-%u-%u", "insert",
           clone_to, clone_len);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), *len + insert_len);
  if (unlikely(!new_buf)) { PFATAL("alloc"); }

  /* Head */

  memcpy(new_buf, *buf, insert_to);

  /* Inserted part */

  memcpy(new_buf + insert_to, insert_buf, insert_len);

  /* Tail */
  memcpy(new_buf + insert_to + insert_len, *buf + insert_to, *len - insert_to);

  *buf = new_buf;
  afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
  *len += insert_len;
}

void bt_mutator_insert_event(afl_state_t *afl, u8 **buf, u32 *len) {
  u32 n = get_num_item(*buf, *len);
  u32 pos = rand_below(afl, n);
  u32 seed = rand_below(afl, RAND_MAX);
  u8  temp_buf[sizeof(item_hdr_t) + sizeof(hci_evt_hdr_t) + BT_MAX_HCI_EVT_SIZE];
  item_hdr_t* item = (item_hdr_t*)temp_buf;
  hci_evt_hdr_t* evt = (hci_evt_hdr_t*)item->payload;
  u8  evt_op, le_evt_op = 0xff;
  evt->param_len = 0xff;

  generate_random_event(seed, &evt_op, &le_evt_op);

  if (evt_op == 3 && has_conn_complete(*buf, *len)) return;

  item->flag = HCI_EVENT_PACKET;
  // temp_buf[4] = HCI_EVENT_PACKET;
  evt->evt_code = evt_op;

  if (le_evt_op != 0xff) temp_buf[7] = le_evt_op;
  item->size = BT_MAX_HCI_EVT_SIZE + sizeof(hci_evt_hdr_t) + 1;

  if (*len + item->size + sizeof(item->size) >= MAX_FILE) return;

  u32 insert_len = item->size + sizeof(item->size);
  bt_mutator_insert_item(afl, buf, len, pos, temp_buf, insert_len);

  //   u32 insert_to = 0;

  //   u32 i = 0;
  //   u32 cnt = 0;
  //   while (i < *len) {
  //     u32  size = *(int *)(*buf + i);
  //     if (cnt == pos) {
  //       insert_to = i;
  //       break;
  //     }
  //     cnt++;
  //     i += (4 + size);
  //   }

  // #ifdef INTROSPECTION
  //   snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s-%u-%u", "insert",
  //            clone_to, clone_len);
  //   strcat(afl->mutation, afl->m_tmp);
  // #endif
  //   u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), *len + insert_len);
  //   if (unlikely(!new_buf)) { PFATAL("alloc"); }

  //   /* Head */

  //   memcpy(new_buf, *buf, insert_to);

  //   /* Inserted part */

  //   memcpy(new_buf + insert_to, temp_buf, insert_len);

  //   /* Tail */
  //   memcpy(new_buf + insert_to + insert_len, *buf + insert_to, *len -
  //   insert_to);

  //   *buf = new_buf;
  //   afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
  //   *len += insert_len;
}

void bt_mutator_delete_event(afl_state_t *afl, u8 *buf, u32 *len) {
  u32 n;
  u32 to_delete, delete_len, delete_pos;
  u32 i, cnt;
  item_hdr_t* item;

  n = get_num_hci(buf, *len);
  if (n == 1) return;
  to_delete = rand_below(afl, n);
  delete_len = 0;
  delete_pos = 0;

  while (i < *len) {
    item = (item_hdr_t*)(buf + i);
    if (item->flag == HCI_EVENT_PACKET) {
      if (cnt == to_delete) {
        delete_pos = i;
        delete_len = item->size + sizeof(item->size);
        break;
      }
      cnt++;
    }
    i += (item->size + sizeof(item->size));
  }

  memmove(buf, buf + delete_pos + delete_len, *len - delete_pos - delete_len);
  *len -= delete_len;
}


