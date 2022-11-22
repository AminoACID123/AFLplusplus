#include "gap.h"
#define NUM_PARAM 12
#define MAX_INPUT 4
#define MAX_OUTPUT 1
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
void *arg_in[MAX_INPUT];
void *arg_out[MAX_OUTPUT];
void *context[NUM_PARAM];
u32   context_len[NUM_PARAM] = { 1, 1, 6, 1, 2, 1, 1, 1, 1, 2, 2};

static int f1(bd_addr_t addr, hci_link_type_t link_type){return 1;}
bd_addr_type_t e3(u8 i) {
switch(i) {
case 0: return BD_ADDR_TYPE_LE_PUBLIC;break;
case 1: return BD_ADDR_TYPE_LE_RANDOM;break;
case 2: return BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_PUBLIC;break;
case 3: return BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_RANDOM;break;
case 4: return BD_ADDR_TYPE_SCO;break;
case 5: return BD_ADDR_TYPE_ACL;break;
}
}
gap_security_mode_t e5(u8 i) {
switch(i) {
case 0: return GAP_SECURITY_MODE_1;break;
case 1: return GAP_SECURITY_MODE_2;break;
case 2: return GAP_SECURITY_MODE_3;break;
case 3: return GAP_SECURITY_MODE_4;break;
}
}
gap_security_level_t e6(u8 i) {
switch(i) {
case 0: return LEVEL_0;break;
case 1: return LEVEL_1;break;
case 2: return LEVEL_2;break;
case 3: return LEVEL_3;break;
}
}
link_key_type_t e7(u8 i) {
switch(i) {
case 0: return INVALID_LINK_KEY;break;
case 1: return COMBINATION_KEY;break;
case 2: return LOCAL_UNIT_KEY;break;
case 3: return REMOTE_UNIT_KEY;break;
case 4: return DEBUG_COMBINATION_KEY;break;
case 5: return UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P192;break;
case 6: return AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P192;break;
case 7: return CHANGED_COMBINATION_KEY;break;
case 8: return UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P256;break;
case 9: return AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P256;break;
}
}
hci_role_t e8(u8 i) {
switch(i) {
case 0: return HCI_ROLE_MASTER;break;
case 1: return HCI_ROLE_SLAVE;break;
}
}
void harness_init() {
  for (int i = 0; i < NUM_PARAM; i++)
    context[i] = malloc(sizeof(char) * context_len[i]);
}
void operation0() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_read_rssi(_i0);
}

void operation1() {
  u8* _o0 = context[2];
  gap_local_bd_addr(_o0);
}

void operation2() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_disconnect(*(hci_con_handle_t*)_i0);
}

void operation3() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_get_connection_type(*(hci_con_handle_t*)_i0);
}

void operation4() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_get_role(*(hci_con_handle_t*)_i0);
}

void operation5() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  hci_role_t _i1 = e8(*(u8*)arg_in[2]);
  gap_request_role(*(hci_con_handle_t*)_i0, _i1);
}

void operation6() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  _i0[_s0-1]=0;
  gap_set_local_name(_i0);
}

void operation7() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  _i0[_s0-1]=0;
  gap_set_extended_inquiry_response(_i0);
}

void operation8() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_class_of_device(*(u32*)_i0);
}

void operation9() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_default_link_policy_settings(*(u16*)_i0);
}

void operation10() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_allow_role_switch(*(bool*)_i0);
}

void operation11() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_link_supervision_timeout(*(u16*)_i0);
}

void operation12() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_enable_link_watchdog(*(u16*)_i0);
}

void operation13() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_bondable_mode(*(bool*)_i0);
}

void operation14() {
  gap_get_bondable_mode();
}

void operation15() {
  gap_security_mode_t _i0 = e5(*(u8*)arg_in[0]);
  gap_set_security_mode(_i0);
}

void operation16() {
  gap_get_security_mode();
}

void operation17() {
  gap_security_level_t _i0 = e6(*(u8*)arg_in[0]);
  gap_set_security_level(_i0);
}

void operation18() {
  gap_get_security_level();
}

void operation19() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_secure_connections_only_mode(*(bool*)_i0);
}

void operation20() {
  gap_get_secure_connections_only_mode();
}

void operation21() {
  gap_security_level_t _i0 = e6(*(u8*)arg_in[0]);
  gap_set_minimal_service_security_level(_i0);
}

void operation22() {
  gap_register_classic_connection_filter(f1);
}

void operation23() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_set_enable(*_i0);
}

void operation24() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_set_io_capability(*(int*)_i0);
}

void operation25() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_set_authentication_requirement(*(int*)_i0);
}

void operation26() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_secure_connections_enable(*(bool*)_i0);
}

void operation27() {
  gap_secure_connections_active();
}

void operation28() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_set_auto_accept(*_i0);
}

void operation29() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_required_encryption_key_size(*(u8*)_i0);
}

void operation30() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_dedicated_bonding(*(bd_addr_t*)_i0, *_i1);
}

void operation31() {
  link_key_type_t _i0 = e7(*(u8*)arg_in[0]);
  gap_security_level_for_link_key_type(_i0);
}

typedef void (*fun_ptr)();
fun_ptr FUZZ_LIST[] = {
  &operation0,
  &operation1,
  &operation2,
  &operation3,
  &operation4,
  &operation5,
  &operation6,
  &operation7,
  &operation8,
  &operation9,
  &operation10,
  &operation11,
  &operation12,
  &operation13,
  &operation14,
  &operation15,
  &operation16,
  &operation17,
  &operation18,
  &operation19,
  &operation20,
  &operation21,
  &operation22,
  &operation23,
  &operation24,
  &operation25,
  &operation26,
  &operation27,
  &operation28,
  &operation29,
  &operation30,
  &operation31
};

