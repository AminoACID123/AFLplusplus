#include "ble/sm.h"
#include "gap.h"
#include "l2cap.h"
#include "stdlib.h"
#define MAX_INPUT 14
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
void *arg_in[MAX_INPUT];
extern u8* __afl_area3_ptr;
le_advertising_set_t le_adv_set;
static int f1(bd_addr_t addr, hci_link_type_t link_type){return 1;}
int get_oob_data_callback(uint8_t address_type, bd_addr_t addr, uint8_t * oob_data){return 1;}
void done_callback(u8* hash){}
int get_sc_oob_data_callback(uint8_t address_type, bd_addr_t addr, uint8_t * oob_sc_peer_confirm, uint8_t * oob_sc_peer_random){return 1;}
bool get_ltk_callback(hci_con_handle_t con_handle, uint8_t address_type, bd_addr_t addr, uint8_t * ltk){return true;}
void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){}
io_capability_t e4(u8 i) {
  switch(i) {
    case 0: return IO_CAPABILITY_DISPLAY_ONLY;break;
    case 1: return IO_CAPABILITY_DISPLAY_YES_NO;break;
    case 2: return IO_CAPABILITY_KEYBOARD_DISPLAY;break;
    case 3: return IO_CAPABILITY_KEYBOARD_ONLY;break;
    case 4: return IO_CAPABILITY_NO_INPUT_NO_OUTPUT;break;
    default: return IO_CAPABILITY_DISPLAY_ONLY;
}
}
bd_addr_type_t e5(u8 i) {
  switch(i) {
    case 0: return BD_ADDR_TYPE_ACL;break;
    case 1: return BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_PUBLIC;break;
    case 2: return BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_RANDOM;break;
    case 3: return BD_ADDR_TYPE_LE_PUBLIC;break;
    case 4: return BD_ADDR_TYPE_LE_RANDOM;break;
    case 5: return BD_ADDR_TYPE_SCO;break;
    default: return BD_ADDR_TYPE_ACL;
}
}
hci_service_type_t e7(u8 i) {
  switch(i) {
    case 0: return HCI_SERVICE_TYPE_BEST_EFFORT;break;
    case 1: return HCI_SERVICE_TYPE_GUARANTEED;break;
    case 2: return HCI_SERVICE_TYPE_NO_TRAFFIC;break;
    default: return HCI_SERVICE_TYPE_BEST_EFFORT;
}
}
gap_security_mode_t e9(u8 i) {
  switch(i) {
    case 0: return GAP_SECURITY_MODE_1;break;
    case 1: return GAP_SECURITY_MODE_2;break;
    case 2: return GAP_SECURITY_MODE_3;break;
    case 3: return GAP_SECURITY_MODE_4;break;
    default: return GAP_SECURITY_MODE_1;
}
}
gap_random_address_type_t e10(u8 i) {
  switch(i) {
    case 0: return GAP_RANDOM_ADDRESS_NON_RESOLVABLE;break;
    case 1: return GAP_RANDOM_ADDRESS_RESOLVABLE;break;
    case 2: return GAP_RANDOM_ADDRESS_TYPE_STATIC;break;
    default: return GAP_RANDOM_ADDRESS_NON_RESOLVABLE;
}
}
gap_security_level_t e11(u8 i) {
  switch(i) {
    case 0: return LEVEL_0;break;
    case 1: return LEVEL_1;break;
    case 2: return LEVEL_2;break;
    case 3: return LEVEL_3;break;
    default: return LEVEL_0;
}
}
link_key_type_t e12(u8 i) {
  switch(i) {
    case 0: return AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P192;break;
    case 1: return AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P256;break;
    case 2: return CHANGED_COMBINATION_KEY;break;
    case 3: return COMBINATION_KEY;break;
    case 4: return DEBUG_COMBINATION_KEY;break;
    case 5: return LOCAL_UNIT_KEY;break;
    case 6: return REMOTE_UNIT_KEY;break;
    case 7: return UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P192;break;
    case 8: return UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P256;break;
    default: return AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P192;
}
}
page_scan_type_t e13(u8 i) {
  switch(i) {
    case 0: return PAGE_SCAN_MODE_INTERLACED;break;
    case 1: return PAGE_SCAN_MODE_STANDARD;break;
    default: return PAGE_SCAN_MODE_INTERLACED;
}
}
hci_role_t e14(u8 i) {
  switch(i) {
    case 0: return HCI_ROLE_MASTER;break;
    case 1: return HCI_ROLE_SLAVE;break;
    default: return HCI_ROLE_MASTER;
}
}
void operation0() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_read_rssi(*(hci_con_handle_t*)_i0);
}

void operation1() {
  u8* _o0 = __afl_area3_ptr + 0;
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
  hci_role_t _i1 = e14(*(u8*)arg_in[2]);
  gap_request_role(_i0, _i1);
}

void operation6() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  _i0[_s0-1]=0;
  gap_set_local_name((char*)_i0);
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
  gap_security_mode_t _i0 = e9(*(u8*)arg_in[0]);
  gap_set_security_mode(_i0);
}

void operation16() {
  gap_get_security_mode();
}

void operation17() {
  gap_security_level_t _i0 = e11(*(u8*)arg_in[0]);
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
  gap_security_level_t _i0 = e11(*(u8*)arg_in[0]);
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
  link_key_type_t _i0 = e12(*(u8*)arg_in[0]);
  gap_security_level_for_link_key_type(_i0);
}

void operation32() {
  link_key_type_t _i0 = e12(*(u8*)arg_in[0]);
  gap_secure_connection_for_link_key_type(_i0);
}

void operation33() {
  link_key_type_t _i0 = e12(*(u8*)arg_in[0]);
  gap_authenticated_for_link_key_type(_i0);
}

void operation34() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_security_level(*(hci_con_handle_t*)_i0);
}

void operation35() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_security_level_t _i1 = e11(*(u8*)arg_in[2]);
  gap_request_security_level(*(hci_con_handle_t*)_i0, _i1);
}

void operation36() {
  gap_security_level_t _i0 = e11(*(u8*)arg_in[0]);
  gap_mitm_protection_required_for_security_level(_i0);
}

void operation37() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_set_page_scan_activity(*(u16*)_i0, *(u16*)_i1);
}

void operation38() {
  page_scan_type_t _i0 = e13(*(u8*)arg_in[0]);
  gap_set_page_scan_type(_i0);
}

void operation39() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_page_timeout(*(u16*)_i0);
}

void operation40() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  gap_set_scan_params(*(u8*)_i0, *(u16*)_i1, *(u16*)_i2, *(u8*)_i3);
}

void operation41() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  gap_set_scan_parameters(*(u8*)_i0, *(u16*)_i1, *(u16*)_i2);
}

void operation42() {
  gap_start_scan();
}

void operation43() {
  gap_stop_scan();
}

void operation44() {
  gap_random_address_type_t _i0 = e10(*(u8*)arg_in[0]);
  gap_random_address_set_mode(_i0);
}

void operation45() {
  gap_random_address_get_mode();
}

void operation46() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_random_address_set_update_period(*(u32*)_i0);
}

void operation47() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_random_address_set(_i0);
}

void operation48() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_advertisements_set_data(*(u8*)_i0, _i1);
}

void operation49() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  u8* _i5 = arg_in[10];
  u32 _s5 = *(u32*)arg_in[11];
  u8* _i6 = arg_in[12];
  u32 _s6 = *(u32*)arg_in[13];
  gap_advertisements_set_params(*(u16*)_i0, *(u16*)_i1, *(u8*)_i2, *(u8*)_i3, _i4, *(u8*)_i5, *(u8*)_i6);
}

void operation50() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_advertisements_enable(*_i0);
}

void operation51() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_scan_response_set_data(_s0, _i0);
}

void operation52() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  bd_addr_type_t _i1 = e5(*(u8*)arg_in[2]);
  bd_addr_type_t _i2 = e5(*(u8*)arg_in[4]);
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  le_extended_advertising_parameters_t param;
  param.own_address_type = _i1;
  param.peer_address_type = _i2;
  memcpy(param.peer_address, _i3, 6);
  param.advertising_event_properties = *(u16*)_i0;
  param.primary_advertising_interval_min = *(u16*)(_i0 + 2);
  param.primary_advertising_interval_max = *(u16*)(_i0 + 4);
  param.primary_advertising_channel_map = *(u8*)(_i0 + 6);
  param.advertising_filter_policy = *(u8*)(_i0 + 7);
  param.advertising_tx_power = *(u8*)(_i0 + 8);
  param.primary_advertising_phy = *(u8*)(_i0 + 9);
  param.secondary_advertising_max_skip = *(u8*)(_i0 + 10);
  param.secondary_advertising_phy = *(u8*)(_i0 + 11);
  param.advertising_sid = *(u8*)(_i0 + 12);
  param.scan_request_notification_enable = *(u8*)(_i0 + 13);
  gap_extended_advertising_setup(&le_adv_set, &param, _i4);
}

void operation53() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  bd_addr_type_t _i1 = e5(*(u8*)arg_in[2]);
  bd_addr_type_t _i2 = e5(*(u8*)arg_in[4]);
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  le_extended_advertising_parameters_t param;
  param.own_address_type = _i1;
  param.peer_address_type = _i2;
  memcpy(param.peer_address, _i3, 6);
  param.advertising_event_properties = *(u16*)_i0;
  param.primary_advertising_interval_min = *(u16*)(_i0 + 2);
  param.primary_advertising_interval_max = *(u16*)(_i0 + 4);
  param.primary_advertising_channel_map = *(u8*)(_i0 + 6);
  param.advertising_filter_policy = *(u8*)(_i0 + 7);
  param.advertising_tx_power = *(u8*)(_i0 + 8);
  param.primary_advertising_phy = *(u8*)(_i0 + 9);
  param.secondary_advertising_max_skip = *(u8*)(_i0 + 10);
  param.secondary_advertising_phy = *(u8*)(_i0 + 11);
  param.advertising_sid = *(u8*)(_i0 + 12);
  param.scan_request_notification_enable = *(u8*)(_i0 + 13);
  gap_extended_advertising_set_params(*(u8*)_i4, &param);
}

void operation54() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  le_extended_advertising_parameters_t param;
  gap_extended_advertising_get_params(*(u8*)_i0, &param);
}

void operation55() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  le_periodic_advertising_parameters_t param;
  param.periodic_advertising_interval_min = *(u16*)_i0;
  param.periodic_advertising_interval_max = *(u16*)(_i0+2);
  param.periodic_advertising_properties = *(u16*)(_i0+4);
  gap_periodic_advertising_set_params(*_i1, &param);
}

void operation56() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  le_periodic_advertising_parameters_t param;
  gap_periodic_advertising_get_params(*_i0, &param);
}

void operation57() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_extended_advertising_set_random_address(*_i0, _i1);
}

void operation58() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_extended_advertising_set_adv_data(*_i0, _s1, _i1);
}

void operation59() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_extended_advertising_set_scan_response_data(*_i0, _s1, _i1);
}

void operation60() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_periodic_advertising_set_data(*_i0, _s1, _i1);
}

void operation61() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  gap_extended_advertising_start(*_i0, *(u16*)_i1, *_i2);
}

void operation62() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_extended_advertising_stop(*_i0);
}

void operation63() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_periodic_advertising_start(*_i0, *(bool*)_i1);
}

void operation64() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_periodic_advertising_stop(*_i0);
}

void operation65() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_extended_advertising_remove(*_i0);
}

void operation66() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_connection_parameters(*(u16*)_i0, *(u16*)&_i0[2], *(u16*)&_i0[4], *(u16*)&_i0[6], *(u16*)&_i0[8], *(u16*)&_i0[10], *(u16*)&_i0[12], *(u16*)&_i0[14]);
}

void operation67() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_request_connection_parameter_update(*(hci_con_handle_t*)_i0, *(u16*)_i1, *(u16*)&_i1[2], *(u16*)&_i1[4], *(u16*)&_i1[6]);
}

void operation68() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_update_connection_parameters(*(hci_con_handle_t*)_i0, *(u16*)_i1, *(u16*)&_i1[2], *(u16*)&_i1[4], *(u16*)&_i1[6]);
}

void operation69() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  le_connection_parameter_range_t r;
  memcpy(&r, _i0, 12);
  gap_set_connection_parameter_range(&r);
}

void operation70() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  le_connection_parameter_range_t r;
  memcpy(&r, _i0, 12);
  gap_connection_parameter_range_included(&r, *(u16*)&_i0[12], *(u16*)&_i0[14], *(u16*)&_i0[16], *(u16*)&_i0[18]);
}

void operation71() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_set_max_number_peripheral_connections(*_i0);
}

void operation72() {
  bd_addr_type_t _i0 = e5(*(u8*)arg_in[0]);
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_whitelist_add(_i0, _i1);
}

void operation73() {
  bd_addr_type_t _i0 = e5(*(u8*)arg_in[0]);
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_whitelist_remove(_i0, _i1);
}

void operation74() {
  gap_whitelist_clear();
}

void operation75() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  bd_addr_type_t _i1 = e5(*(u8*)arg_in[2]);
  gap_connect(_i0, _i1);
}

void operation76() {
  gap_connect_with_whitelist();
}

void operation77() {
  gap_connect_cancel();
}

void operation78() {
  bd_addr_type_t _i0 = e5(*(u8*)arg_in[0]);
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_auto_connection_start(_i0, _i1);
}

void operation79() {
  bd_addr_type_t _i0 = e5(*(u8*)arg_in[0]);
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_auto_connection_stop(_i0, _i1);
}

void operation80() {
  gap_auto_connection_stop_all();
}

void operation81() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  gap_le_set_phy(*(hci_con_handle_t*)_i0, *_i1, *_i2, *_i3, *_i4);
}

void operation82() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_le_connection_interval(*(hci_con_handle_t*)_i0);
}

void operation83() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_encryption_key_size(*(hci_con_handle_t*)_i0);
}

void operation84() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_authenticated(*(hci_con_handle_t*)_i0);
}

void operation85() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_secure_connection(*(hci_con_handle_t*)_i0);
}

void operation86() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_authorization_state(*(hci_con_handle_t*)_i0);
}

void operation87() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_bonded(*(hci_con_handle_t*)_i0);
}

void operation88() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_connectable_control(*_i0);
}

void operation89() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_discoverable_control(*_i0);
}

void operation90() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_inquiry_start(*_i0);
}

void operation91() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  gap_inquiry_periodic_start(*_i0, *(u16*)_i1, *(u16*)_i2);
}

void operation92() {
  gap_inquiry_stop();
}

void operation93() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_inquiry_set_lap(*(u32*)_i0);
}

void operation94() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_inquiry_set_scan_activity(*(u16*)_i0, *(u16*)_i1);
}

void operation95() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  gap_remote_name_request(_i0, *_i1, *(u16*)_i2);
}

void operation96() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  _i1[_s1 - 1] = 0;
  gap_pin_code_response(_i0, (char*)_i1);
}

void operation97() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_pin_code_response_binary(_i0, _i1, _s1);
}

void operation98() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_pin_code_negative(_i0);
}

void operation99() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_ssp_passkey_response(_i0, *(u32*)_i1);
}

void operation100() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_passkey_negative(_i0);
}

void operation101() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_confirmation_response(_i0);
}

void operation102() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_confirmation_negative(_i0);
}

void operation103() {
  gap_ssp_generate_oob_data();
}

void operation104() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  gap_ssp_remote_oob_data(_i0, _i1, _i2, _i3, _i4);
}

void operation105() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_io_capabilities_response(_i0);
}

void operation106() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_ssp_io_capabilities_negative(_i0);
}

void operation107() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  link_key_type_t _i2 = e12(*(u8*)arg_in[4]);
  gap_send_link_key_response(_i0, _i1, _i2);
}

void operation108() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  gap_sniff_mode_enter(*(hci_con_handle_t*)_i0, *(u16*)_i1, *(u16*)_i2, *(u16*)_i3, *(u16*)_i4);
}

void operation109() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_sniff_mode_exit(*(hci_con_handle_t*)_i0);
}

void operation110() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  gap_sniff_subrating_configure(*(hci_con_handle_t*)_i0, *(u16*)_i1, *(u16*)_i2, *(u16*)_i3);
}

void operation111() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  hci_service_type_t _i1 = e7(*(u8*)arg_in[2]);
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  u8* _i5 = arg_in[10];
  u32 _s5 = *(u32*)arg_in[11];
  gap_qos_set(*(hci_con_handle_t*)_i0, _i1, *(u32*)_i2, *(u32*)_i3, *(u32*)_i4, *(u32*)_i5);
}

void operation112() {
  u8 addr_type;
  bd_addr_t addr;
  gap_le_get_own_address(&addr_type, addr);
}

void operation113() {
  u8 addr_type;
  bd_addr_t addr;
  gap_le_get_own_advertisements_address(&addr_type, addr);
}

void operation114() {
  u8 addr_type;
  bd_addr_t addr;
  gap_le_get_own_connection_address(&addr_type, addr);
}

void operation115() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_reconnect_security_setup_active(*(hci_con_handle_t*)_i0);
}

void operation116() {
  bd_addr_type_t _i0 = e5(*(u8*)arg_in[0]);
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  gap_delete_bonding(_i0, _i1);
}

void operation117() {
  gap_load_resolving_list_from_le_device_db();
}

void operation118() {
  gap_get_persistent_irk();
}

void operation119() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_set_er(_i0);
}

void operation120() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_set_ir(_i0);
}

void operation121() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_set_accepted_stk_generation_methods(*(u8*)_i0);
}

void operation122() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  sm_set_encryption_key_size_range(*(u8*)_i0, *(u8*)_i1);
}

void operation123() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_set_authentication_requirements(*(u8*)_i0);
}

void operation124() {
  io_capability_t _i0 = e4(*(u8*)arg_in[0]);
  sm_set_io_capabilities(_i0);
}

void operation125() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_set_secure_connections_only_mode(*_i0);
}

void operation126() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_set_request_security(*_i0);
}

void operation127() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_send_security_request(*(hci_con_handle_t*)_i0);
}

void operation128() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_bonding_decline(*(hci_con_handle_t*)_i0);
}

void operation129() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_just_works_confirm(*(hci_con_handle_t*)_i0);
}

void operation130() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_numeric_comparison_confirm(*(hci_con_handle_t*)_i0);
}

void operation131() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  sm_passkey_input(*(hci_con_handle_t*)_i0, *(u32*)_i1);
}

void operation132() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  sm_keypress_notification(*(hci_con_handle_t*)_i0, *_i1);
}

void operation133() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_request_pairing(*(hci_con_handle_t*)_i0);
}

void operation134() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_authorization_decline(*(hci_con_handle_t*)_i0);
}

void operation135() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_authorization_grant(*(hci_con_handle_t*)_i0);
}

void operation136() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_cmac_ready();
}

void operation137() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  u8* _i2 = arg_in[4];
  u32 _s2 = *(u32*)arg_in[5];
  u8* _i3 = arg_in[6];
  u32 _s3 = *(u32*)arg_in[7];
  u8* _i4 = arg_in[8];
  u32 _s4 = *(u32*)arg_in[9];
  sm_cmac_signed_write_start(_i0, *_i1, *(hci_con_handle_t*)_i2,_s3, _i3, *(u32*)_i3, done_callback);
}

void operation138() {
  bd_addr_type_t _i0 = e5(*(u8*)arg_in[0]);
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  sm_address_resolution_lookup(_i0, _i1);
}

void operation139() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_identity_resolving_state(*(hci_con_handle_t*)_i0);
}

void operation140() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_le_device_index(*(hci_con_handle_t*)_i0);
}

void operation141() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_use_fixed_passkey_in_display_role(*(u32*)_i0);
}

void operation142() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  sm_allow_ltk_reconstruction_without_le_device_db_entry(*_i0);
}

void operation143() {
  sm_generate_sc_oob_data(NULL);
}

void operation144() {
  sm_register_sc_oob_data_callback(get_sc_oob_data_callback);
}

void operation145() {
  sm_register_ltk_callback(get_sc_oob_data_callback);
}

void operation146() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  u8* _i1 = arg_in[2];
  u32 _s1 = *(u32*)arg_in[3];
  l2cap_create_channel(packet_handler, _i0, *(u16*)_i1, 255, (u16*)__afl_area3_ptr);
}

void operation147() {
  u8* _i0 = arg_in[0];
  u32 _s0 = *(u32*)arg_in[1];
  gap_security_level_t _i1 = e11(*(u8*)arg_in[2]);
  l2cap_register_service(packet_handler, *(u16*)_i0, 100, _i1);
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
  &operation31,
  &operation32,
  &operation33,
  &operation34,
  &operation35,
  &operation36,
  &operation37,
  &operation38,
  &operation39,
  &operation40,
  &operation41,
  &operation42,
  &operation43,
  &operation44,
  &operation45,
  &operation46,
  &operation47,
  &operation48,
  &operation49,
  &operation50,
  &operation51,
  &operation52,
  &operation53,
  &operation54,
  &operation55,
  &operation56,
  &operation57,
  &operation58,
  &operation59,
  &operation60,
  &operation61,
  &operation62,
  &operation63,
  &operation64,
  &operation65,
  &operation66,
  &operation67,
  &operation68,
  &operation69,
  &operation70,
  &operation71,
  &operation72,
  &operation73,
  &operation74,
  &operation75,
  &operation76,
  &operation77,
  &operation78,
  &operation79,
  &operation80,
  &operation81,
  &operation82,
  &operation83,
  &operation84,
  &operation85,
  &operation86,
  &operation87,
  &operation88,
  &operation89,
  &operation90,
  &operation91,
  &operation92,
  &operation93,
  &operation94,
  &operation95,
  &operation96,
  &operation97,
  &operation98,
  &operation99,
  &operation100,
  &operation101,
  &operation102,
  &operation103,
  &operation104,
  &operation105,
  &operation106,
  &operation107,
  &operation108,
  &operation109,
  &operation110,
  &operation111,
  &operation112,
  &operation113,
  &operation114,
  &operation115,
  &operation116,
  &operation117,
  &operation118,
  &operation119,
  &operation120,
  &operation121,
  &operation122,
  &operation123,
  &operation124,
  &operation125,
  &operation126,
  &operation127,
  &operation128,
  &operation129,
  &operation130,
  &operation131,
  &operation132,
  &operation133,
  &operation134,
  &operation135,
  &operation136,
  &operation137,
  &operation138,
  &operation139,
  &operation140,
  &operation141,
  &operation142,
  &operation143,
  &operation144,
  &operation145,
  &operation146,
  &operation147
};

