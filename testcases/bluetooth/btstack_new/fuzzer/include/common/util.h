
#ifndef BTFUZZ_UTIL_H
#define BTFUZZ_UTIL_H


#include "common/bluetooth.h"
#include "common/type.h"
#include <stdint.h>
#include <string.h>

#define UNUSED(v)          (void)(v)

/**
 * @brief The device name type
 */
#define DEVICE_NAME_LEN 248
typedef uint8_t device_name_t[DEVICE_NAME_LEN+1]; 

/* API_START */

/**
 * @brief Minimum function for uint32_t
 * @param a
 * @param b
 * @return value
 */
uint32_t btfuzz_min(uint32_t a, uint32_t b);

/**
 * @brief Maximum function for uint32_t
 * @param a
 * @param b
 * @return value
 */
uint32_t btfuzz_max(uint32_t a, uint32_t b);

/**
 * @brief Calculate delta between two uint32_t points in time
 * @return time_a - time_b - result > 0 if time_a is newer than time_b
 */
int32_t btfuzz_time_delta(uint32_t time_a, uint32_t time_b);

/**
 * @brief Calculate delta between two uint16_t points in time
 * @return time_a - time_b - result > 0 if time_a is newer than time_b
 */
int16_t btfuzz_time16_delta(uint16_t time_a, uint16_t time_b);

/** 
 * @brief Read 16/24/32 bit little endian value from buffer
 * @param buffer
 * @param position in buffer
 * @return value
 */
uint16_t little_endian_read_16(const uint8_t * buffer, int position);
uint32_t little_endian_read_24(const uint8_t * buffer, int position);
uint32_t little_endian_read_32(const uint8_t * buffer, int position);

/** 
 * @brief Write 16/32 bit little endian value into buffer
 * @param buffer
 * @param position in buffer
 * @param value
 */
void little_endian_store_16(uint8_t * buffer, uint16_t position, uint16_t value);
void little_endian_store_24(uint8_t * buffer, uint16_t position, uint32_t value);
void little_endian_store_32(uint8_t * buffer, uint16_t position, uint32_t value);

/** 
 * @brief Read 16/24/32 bit big endian value from buffer
 * @param buffer
 * @param position in buffer
 * @return value
 */
uint32_t big_endian_read_16(const uint8_t * buffer, int position);
uint32_t big_endian_read_24(const uint8_t * buffer, int position);
uint32_t big_endian_read_32(const uint8_t * buffer, int position);

/** 
 * @brief Write 16/32 bit big endian value into buffer
 * @param buffer
 * @param position in buffer
 * @param value
 */
void big_endian_store_16(uint8_t * buffer, uint16_t position, uint16_t value);
void big_endian_store_24(uint8_t * buffer, uint16_t position, uint32_t value);
void big_endian_store_32(uint8_t * buffer, uint16_t position, uint32_t value);


/**
 * @brief Swap bytes in 16 bit integer
 */
static inline uint16_t btfuzz_flip_16(uint16_t value){
    return (uint16_t)((value & 0xffu) << 8) | (value >> 8);
}

/** 
 * @brief Check for big endian system
 * @return 1 if on big endian
 */
static inline int btfuzz_is_big_endian(void){
	uint16_t sample = 0x0100;
	return (int) *(uint8_t*) &sample;
}

/** 
 * @brief Check for little endian system
 * @return 1 if on little endian
 */
static inline int btfuzz_is_little_endian(void){
	uint16_t sample = 0x0001;
	return (int) *(uint8_t*) &sample;
}

/**
 * @brief Copy from source to destination and reverse byte order
 * @param src
 * @param dest
 * @param len
 */
void reverse_bytes(const uint8_t * src, uint8_t * dest, int len);

/**
 * @brief Wrapper around reverse_bytes for common buffer sizes
 * @param src
 * @param dest
 */
void reverse_24 (const uint8_t * src, uint8_t * dest);
void reverse_48 (const uint8_t * src, uint8_t * dest);
void reverse_56 (const uint8_t * src, uint8_t * dest);
void reverse_64 (const uint8_t * src, uint8_t * dest);
void reverse_128(const uint8_t * src, uint8_t * dest);
void reverse_256(const uint8_t * src, uint8_t * dest);


/** 
 * @brief ASCII character for 4-bit nibble
 * @return character
 */
char char_for_nibble(int nibble);

/**
 * @brif 4-bit nibble from ASCII character
 * @return value
 */
int nibble_for_char(char c);

/**
 * @brief Compare two Bluetooth addresses
 * @param a
 * @param b
 * @return 0 if equal
 */
int bd_addr_cmp(const bd_addr_t a, const bd_addr_t b);

/**
 * @brief Copy Bluetooth address
 * @param dest
 * @param src
 */
void bd_addr_copy(bd_addr_t dest, const bd_addr_t src);

/**
 * @brief Use printf to write hexdump as single line of data
 */
void printf_hexdump(const void * data, int size);

/**
 * @brief Create human readable representation for UUID128
 * @note uses fixed global buffer
 * @return pointer to UUID128 string
 */
char * uuid128_to_str(const uint8_t * uuid);

/**
 * @brief Create human readable represenationt of Bluetooth address
 * @note uses fixed global buffer
 * @param delimiter
 * @return pointer to Bluetooth address string
 */
char * bd_addr_to_str_with_delimiter(const bd_addr_t addr, char delimiter);

/**
 * @brief Create human readable represenationt of Bluetooth address
 * @note uses fixed global buffer
 * @return pointer to Bluetooth address string
 */
char * bd_addr_to_str(const bd_addr_t addr);

/**
 * @brief Replace address placeholder '00:00:00:00:00:00' with Bluetooth address
 * @param buffer
 * @param size
 * @param address
 */
void btfuzz_replace_bd_addr_placeholder(uint8_t * buffer, uint16_t size, const bd_addr_t address);

/** 
 * @brief Parse Bluetooth address
 * @param address_string
 * @param buffer for parsed address
 * @return 1 if string was parsed successfully
 */
int sscanf_bd_addr(const char * addr_string, bd_addr_t addr);

/**
 * @brief Constructs UUID128 from 16 or 32 bit UUID using Bluetooth base UUID
 * @param uuid128 output buffer
 * @param short_uuid
 */
void uuid_add_bluetooth_prefix(uint8_t * uuid128, uint32_t short_uuid);

/**
 * @brief Checks if UUID128 has Bluetooth base UUID prefix
 * @param uui128 to test
 * @return 1 if it can be expressed as UUID32
 */
int  uuid_has_bluetooth_prefix(const uint8_t * uuid128);

/**
 * @brief Parse unsigned number 
 * @param str to parse
 * @return value
 */
uint32_t btfuzz_atoi(const char * str);

/**
 * @brief Return number of digits of a uint32 number
 * @param uint32_number
 * @return num_digits
 */
int string_len_for_uint32(uint32_t i);

/**
 * @brief Return number of set bits in a uint32 number
 * @param uint32_number
 * @return num_set_bits
 */
int count_set_bits_uint32(uint32_t x);

/**
 * @brief Check CRC8 using ETSI TS 101 369 V6.3.0.
 * @note Only used by RFCOMM
 * @param data
 * @param len
 * @param check_sum
 */
uint8_t btfuzz_crc8_check(uint8_t * data, uint16_t len, uint8_t check_sum);

/**
 * @brief Calculate CRC8 using ETSI TS 101 369 V6.3.0. 
 * @note Only used by RFCOMM
 * @param data
 * @param len
 */
uint8_t btfuzz_crc8_calc(uint8_t * data, uint16_t len);

/**
 * @brief Get next cid
 * @param current_cid
 * @return next cid skiping 0
 */
uint16_t btfuzz_next_cid_ignoring_zero(uint16_t current_cid);



typedef struct {
	void ** elements;
	u32 size;
	u32 capacity;
}btfuzz_vector_t;

void btfuzz_vector_push_back(btfuzz_vector_t* vec, void* elem);

void* btfuzz_vector_get(btfuzz_vector_t* vec, u32 i);

u32 btfuzz_vector_size(btfuzz_vector_t* vec);



/* Linked List */
	
typedef struct btfuzz_linked_item {
    struct btfuzz_linked_item *next; // <-- next element in list, or NULL
} btfuzz_linked_item_t;

typedef btfuzz_linked_item_t* btfuzz_linked_list_t;

typedef struct {
	int advance_on_next;
    btfuzz_linked_item_t * prev;	// points to the item before the current one
    btfuzz_linked_item_t * curr;	// points to the current item (to detect item removal)
} btfuzz_linked_list_iterator_t;


/**
 * @brief Test if list is empty.
 * @param list
 * @return true if list is empty
 */
bool btfuzz_linked_list_empty(btfuzz_linked_list_t * list);

/**
 * @brief Add item to list as first element.
 * @param list
 * @param item
 * @return true if item was added, false if item already in list
 */
bool btfuzz_linked_list_add(btfuzz_linked_list_t * list, btfuzz_linked_item_t *item);

/**
 * @brief Add item to list as last element.
 * @param list
 * @param item
 * @return true if item was added, false if item already in list
 */
bool btfuzz_linked_list_add_tail(btfuzz_linked_list_t * list, btfuzz_linked_item_t *item);

/**
 * @brief Pop (get + remove) first element.
 * @param list
 * @return first element or NULL if list is empty
 */
btfuzz_linked_item_t * btfuzz_linked_list_pop(btfuzz_linked_list_t * list);

/**
 * @brief Remove item from list
 * @param list
 * @param item
 * @return true if item was removed, false if it is no't in list
 */
bool btfuzz_linked_list_remove(btfuzz_linked_list_t * list, btfuzz_linked_item_t *item);

/**
 * @brief Get first element.
 * @param list
 * @return first element or NULL if list is empty
 */
btfuzz_linked_item_t * btfuzz_linked_list_get_first_item(btfuzz_linked_list_t * list);

/**
 * @brief Get last element.
 * @param list
 * @return first element or NULL if list is empty
 */
btfuzz_linked_item_t * btfuzz_linked_list_get_last_item(btfuzz_linked_list_t * list);   

/**
 * @brief Counts number of items in list
 * @return number of items in list
 */
int btfuzz_linked_list_count(btfuzz_linked_list_t * list);


/**
 * @brief Initialize Linked List Iterator
 * @note robust against removal of current element by btfuzz_linked_list_remove
 * @param it iterator context
 * @param list
 */
void btfuzz_linked_list_iterator_init(btfuzz_linked_list_iterator_t * it, btfuzz_linked_list_t * list);

/**
 * @brief Has next element
 * @param it iterator context
 * @return true if next element is available
 */
bool btfuzz_linked_list_iterator_has_next(btfuzz_linked_list_iterator_t * it);

/**
 * @brief Get next list eleemnt
 * @param it iterator context
 * @return list element
 */
btfuzz_linked_item_t * btfuzz_linked_list_iterator_next(btfuzz_linked_list_iterator_t * it);

/**
 * @brief Remove current list element from list
 * @param it iterator context
 */
void btfuzz_linked_list_iterator_remove(btfuzz_linked_list_iterator_t * it);

/* API_END */

#define cast_define(type, to, from) type to = (type)(from)


	

/* API_END */

#endif
