#include "afl-fuzz.h"
#include "bluetooth.h"

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

typedef void (*bt_mutator)(afl_state_t *, u8 *, u32);

extern u32 get_total_harness();

static inline u32 get_num_item(u8 *buf, u32 len) {
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    cnt++;
    i += (4 + size);
  }
  return cnt;
}

static inline u32 get_num_harness(u8 *buf, u32 len) {
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];
    if (flag == F_API) { cnt++; }
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

int get_parameter_num(u8 *buf, u32 len) {
  u32 i = 0;
  u32 ret = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];

    if (flag == HCI_EVENT_PACKET) {
      ret++;
    } else if (flag == F_API) {
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
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16");
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
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32");
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
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8_");
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
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16_-%u", pos);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 1);
  *(u16 *)(buf + pos) -= 1 + rand_below(afl, ARITH_MAX);
}

void bt_mutator_subtract16_be(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16_BE-%u_%u", pos, num);
  strcat(afl->mutation, afl->m_tmp);
#endif
  u32 pos = rand_below(afl, len - 1);
  u16 num = 1 + rand_below(afl, ARITH_MAX);
  *(u16 *)(buf + pos) = SWAP16(SWAP16(*(u16 *)(buf + pos)) - num);
}

void bt_mutator_add16_le(afl_state_t *afl, u8 *buf, u32 len) {
  if (len < 2) return;
#ifdef INTROSPECTION
  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+-%u", pos);
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

void mutate_parameter(afl_state_t *afl, u8 *buf, u32 len, bt_mutator mutator) {
  u32 param = rand_below(afl, get_parameter_num(buf, len));
  u32 i = 0;
  u32 cnt = 0;
  while (i < len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];

    if (flag == HCI_EVENT_PACKET) {
      if (cnt == param) {
        mutator(afl, buf + i + 5, 255);
        return;
      }
      cnt++;
    } else if (flag == F_API) {
      int j = i + 13;
      int arg_in_cnt = *(int *)(buf + i + 9);
      for (int k = 0; k < arg_in_cnt; k++) {
        int arg_len = *(int *)(buf + j + 4);
        if (cnt == param) {
          mutator(afl, buf + j + 8, arg_len);
          return;
        }
        cnt++;
        j += (8 + arg_len);
      }
    }
    i += (4 + size);
  }
}

extern void generate_random_harness(u32 idx, u32 seed, u8 *out_buf);

void bt_mutator_insert_harness(afl_state_t *afl, u8 **buf, u32 *len) {
  u32 n = get_num_harness(buf, len);
  u32 pos = rand_below(afl, n);
  u32 idx = rand_below(afl, get_total_harness());
  u32 seed = rand_below(afl, UINT32_MAX);
  u8  temp_buf[BT_MAX_BUFFER_SIZE];
  generate_random_harness(idx, seed, temp_buf);

  if (*len + *(int *)temp_buf + 4 >= MAX_FILE) return;

  u32 insert_len = *(int *)temp_buf + 4;
  u32 insert_to;

  int i = 0;
  int cnt = 0;
  while (i < *len) {
    int  size = *(int *)(buf + i);
    char flag = buf[i + 4];
    if (flag == F_API) {
      if (cnt == n) {
        insert_to = i;
        break;
      }
      cnt++;
    }
    i += (4 + size);
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

void bt_mutator_delete_harness(afl_state_t *afl, u8 *buf, u32 *len) {
  u32 n = get_num_harness(buf, len);
}

void bt_mutator_insert_hci(afl_state_t *afl, u8 *buf, u32 *len) {
  u32 n = get_num_hci(buf, len);
}

void bt_mutator_delete_hci(afl_state_t *afl, u8 *buf, u32 *len) {
  u32 n = get_num_hci(buf, len);
}
