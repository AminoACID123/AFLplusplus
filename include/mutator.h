#ifndef MUTATOR
#define MUTATOR


#include "afl-fuzz.h"

typedef void (*bt_mutator)(afl_state_t *, char *, int);

/*********************
* Parameter Mutators *
* ********************/

void bt_mutator_flip_bit(afl_state_t *afl, char *buf, int len);

void bt_mutator_interesting8(afl_state_t *afl, char *buf, int len);

void bt_mutator_interesting16_le(afl_state_t *afl, char *buf, int len);

void bt_mutator_interesting16_be(afl_state_t *afl, char *buf, int len);

void bt_mutator_interesting32_le(afl_state_t *afl, char *buf, int len);

void bt_mutator_interesting32_be(afl_state_t *afl, char *buf, int len);

void bt_mutator_subtract8(afl_state_t *afl, char *buf, int len);

void bt_mutator_add8(afl_state_t *afl, char *buf, int len);

void bt_mutator_subtract16_le(afl_state_t *afl, char *buf, int len);

void bt_mutator_subtract16_be(afl_state_t *afl, char *buf, int len);

void bt_mutator_add16_le(afl_state_t *afl, char *buf, int len);

void bt_mutator_add16_be(afl_state_t *afl, char *buf, int len);

void bt_mutator_subtract32_le(afl_state_t *afl, char *buf, int len);

void bt_mutator_subtract32_be(afl_state_t *afl, char *buf, int len);

void bt_mutator_add32_le(afl_state_t *afl, char *buf, int len);

void bt_mutator_add32_be(afl_state_t *afl, char *buf, int len);

void bt_mutator_random8(afl_state_t *afl, char *buf, int len);

void bt_mutator_increase_byte(afl_state_t *afl, char *buf, int len);

void bt_mutator_decrease_byte(afl_state_t *afl, char *buf, int len);

void bt_mutator_flip_byte(afl_state_t *afl, char *buf, int len);

void mutate_parameter(afl_state_t *afl, char *buf, int len, bt_mutator mutator);

/*************************
* Parameter Mutators End *
* ************************/


/**********************
* Item Mutators Begin *
* *********************/
void bt_mutator_insert_operation(afl_state_t *afl, char **buf, int* len);

void bt_mutator_delete_operation(afl_state_t *afl, char *buf, int* len);

void bt_mutator_insert_packet(afl_state_t *afl, char **buf, int* len);

void bt_mutator_delete_packet(afl_state_t *afl, char* buf, int* len);
/********************
* Item Mutators End *
* *******************/

#endif
