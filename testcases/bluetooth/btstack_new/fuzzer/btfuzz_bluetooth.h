#ifndef D9164AF1_4E22_4376_82E6_9C574FB08463
#define D9164AF1_4E22_4376_82E6_9C574FB08463

#include "btfuzz_type.h"

#define HCI_OPCODE(OGF, OCF) ((OCF) | ((OGF) << 10))

#define HCI_COMMAND_DATA_PACKET 0x01
#define HCI_ACL_DATA_PACKET 0x02
#define HCI_SCO_DATA_PACKET 0x03
#define HCI_EVENT_PACKET 0x04
#define HCI_ISO_DATA_PACKET 0x05

#define L2CAP_CID_SIGNALING 0x0001
#define L2CAP_CID_CONNECTIONLESS_CHANNEL 0x0002
#define L2CAP_CID_ATTRIBUTE_PROTOCOL 0x0004
#define L2CAP_CID_SIGNALING_LE 0x0005
#define L2CAP_CID_SECURITY_MANAGER_PROTOCOL 0x0006
#define L2CAP_CID_BR_EDR_SECURITY_MANAGER 0x0007
#define FIXED_CID(cid)                                                         \
  (cid >= L2CAP_CID_SIGNALING && cid <= L2CAP_CID_BR_EDR_SECURITY_MANAGER)

#define BLUETOOTH_PSM_SDP 0x0001
#define BLUETOOTH_PSM_RFCOMM 0x0003
#define BLUETOOTH_PSM_TCS_BIN 0x0005
#define BLUETOOTH_PSM_TCS_BIN_CORDLESS 0x0007
#define BLUETOOTH_PSM_BNEP 0x000F
#define BLUETOOTH_PSM_HID_CONTROL 0x0011
#define BLUETOOTH_PSM_HID_INTERRUPT 0x0013
#define BLUETOOTH_PSM_UPNP 0x0015
#define BLUETOOTH_PSM_AVCTP 0x0017
#define BLUETOOTH_PSM_AVDTP 0x0019
#define BLUETOOTH_PSM_AVCTP_BROWSING 0x001B
#define BLUETOOTH_PSM_UDI_C_PLANE 0x001D
#define BLUETOOTH_PSM_ATT 0x001F
#define BLUETOOTH_PSM_3DSP 0x0021
#define BLUETOOTH_PSM_LE_PSM_IPSP 0x0023
#define BLUETOOTH_PSM_OTS 0x0025
#define FIXED_PSM(psm)                                                         \
  ((psm % 2 == 1) &&                                                           \
   ((psm <= BLUETOOTH_PSM_TCS_BIN_CORDLESS) ||                                 \
    (psm >= BLUETOOTH_PSM_BNEP && psm <= BLUETOOTH_PSM_OTS)))

#define CLASSIC 0
#define LE 1
#define DUAL 2

typedef enum {
  BD_ADDR_TYPE_LE_PUBLIC = 0,
  BD_ADDR_TYPE_LE_RANDOM = 1,
  BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_PUBLIC = 2,
  BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_RANDOM = 3,
  BD_ADDR_TYPE_SCO = 0xfc,
  BD_ADDR_TYPE_ACL = 0xfd,
  BD_ADDR_TYPE_UNKNOWN = 0xfe, // also used as 'invalid'
} bd_addr_type_t;

#define BD_ADDR_LEN 6
typedef uint8_t bd_addr_t[BD_ADDR_LEN];
typedef uint8_t sm_key_t[16];


#define BT_HCI_CMD_BIT(_byte, _bit) ((8 * _byte) + _bit)

struct bt_ll_hdr {
  u8 preamble;
  u32 access_addr;
} __attribute__((packed));

#define BT_LL_CONN_UPDATE_REQ 0x00
struct bt_ll_conn_update_req {
  u8 win_size;
  u16 win_offset;
  u16 interval;
  u16 latency;
  u16 timeout;
  u16 instant;
} __attribute__((packed));

#define BT_LL_CHANNEL_MAP_REQ 0x01
struct bt_ll_channel_map_req {
  u8 map[5];
  u16 instant;
} __attribute__((packed));

#define BT_LL_TERMINATE_IND 0x02
struct bt_ll_terminate_ind {
  u8 error;
} __attribute__((packed));

#define BT_LL_ENC_REQ 0x03
struct bt_ll_enc_req {
  u64 rand;
  u16 ediv;
  u64 skd;
  u32 iv;
} __attribute__((packed));

#define BT_LL_ENC_RSP 0x04
struct bt_ll_enc_rsp {
  u64 skd;
  u32 iv;
} __attribute__((packed));

#define BT_LL_START_ENC_REQ 0x05

#define BT_LL_START_ENC_RSP 0x06

#define BT_LL_UNKNOWN_RSP 0x07
struct bt_ll_unknown_rsp {
  u8 type;
} __attribute__((packed));

#define BT_LL_FEATURE_REQ 0x08
struct bt_ll_feature_req {
  u8 features[8];
} __attribute__((packed));

#define BT_LL_FEATURE_RSP 0x09
struct bt_ll_feature_rsp {
  u8 features[8];
} __attribute__((packed));

#define BT_LL_PAUSE_ENC_REQ 0x0a

#define BT_LL_PAUSE_ENC_RSP 0x0b

#define BT_LL_VERSION_IND 0x0c
struct bt_ll_version_ind {
  u8 version;
  u16 company;
  u16 subversion;
} __attribute__((packed));

#define BT_LL_REJECT_IND 0x0d
struct bt_ll_reject_ind {
  u8 error;
} __attribute__((packed));

#define BT_LL_PERIPHERAL_FEATURE_REQ 0x0e
struct bt_ll_peripheral_feature_req {
  u8 features[8];
} __attribute__((packed));

#define BT_LL_CONN_PARAM_REQ 0x0f

#define BT_LL_CONN_PARAM_RSP 0x10

#define BT_LL_REJECT_IND_EXT 0x11
struct bt_ll_reject_ind_ext {
  u8 opcode;
  u8 error;
} __attribute__((packed));

#define BT_LL_PING_REQ 0x12

#define BT_LL_PING_RSP 0x13

#define BT_LL_LENGTH_REQ 0x14
struct bt_ll_length {
  u16 rx_len;
  u16 rx_time;
  u16 tx_len;
  u16 tx_time;
} __attribute__((packed));

#define BT_LL_LENGTH_RSP 0x15

#define BT_LL_PHY_REQ 0x16
struct bt_ll_phy {
  u8 tx_phys;
  u8 rx_phys;
} __attribute__((packed));

#define BT_LL_PHY_RSP 0x17

#define BT_LL_PHY_UPDATE_IND 0x18
struct bt_ll_phy_update_ind {
  u8 c_phy;
  u8 p_phy;
  u16 instant;
} __attribute__((packed));

#define BT_LL_MIN_USED_CHANNELS 0x19
struct bt_ll_min_used_channels {
  u8 phys;
  u8 min_channels;
} __attribute__((packed));

#define BT_LL_CTE_REQ 0x1a
struct bt_ll_cte_req {
  u8 cte;
} __attribute__((packed));

#define BT_LL_CTE_RSP 0x1b

#define BT_LL_PERIODIC_SYNC_IND 0x1c
struct bt_ll_periodic_sync_ind {
  u16 id;
  u8 info[18];
  u16 event_count;
  u16 last_counter;
  u8 adv_info;
  u8 phy;
  u8 adv_addr[6];
  u16 sync_counter;
} __attribute__((packed));

#define BT_LL_CLOCK_ACCURACY_REQ 0x1d
struct bt_ll_clock_acc {
  u8 sca;
} __attribute__((packed));

#define BT_LL_CLOCK_ACCURACY_RSP 0x1e

#define BT_LL_CIS_REQ 0x1f
struct bt_ll_cis_req {
  u8 cig;
  u8 cis;
  u8 c_phy;
  u8 p_phy;
  u16 c_sdu;
  u16 p_sdu;
  u8 c_interval[3];
  u8 p_interval[3];
  u8 c_pdu;
  u8 p_pdu;
  u8 nse;
  u8 sub_interval[3];
  u8 bn;
  u8 c_ft;
  u8 p_ft;
  u16 iso_interval;
  u8 offset_min[3];
  u8 offset_max[3];
  u16 conn_event_count;
} __attribute__((packed));

#define BT_LL_CIS_RSP 0x20
struct bt_ll_cis_rsp {
  u8 offset_min[3];
  u8 offset_max[3];
  u16 conn_event_count;
} __attribute__((packed));

#define BT_LL_CIS_IND 0x21
struct bt_ll_cis_ind {
  u32 addr;
  u8 cis_offset[3];
  u8 cig_sync_delay[3];
  u8 cis_sync_delay[3];
  u16 conn_event_count;
} __attribute__((packed));

#define BT_LL_CIS_TERMINATE_IND 0x22
struct bt_ll_cis_term_ind {
  u8 cig;
  u8 cis;
  u8 reason;
} __attribute__((packed));

#define LMP_ESC4(x) ((127 << 8) | (x))

#define BT_LMP_NAME_REQ 1
struct bt_lmp_name_req {
  u8 offset;
} __attribute__((packed));

#define BT_LMP_NAME_RSP 2
struct bt_lmp_name_rsp {
  u8 offset;
  u8 length;
  u8 fragment[14];
} __attribute__((packed));

#define BT_LMP_ACCEPTED 3
struct bt_lmp_accepted {
  u8 opcode;
} __attribute__((packed));

#define BT_LMP_NOT_ACCEPTED 4
struct bt_lmp_not_accepted {
  u8 opcode;
  u8 error;
} __attribute__((packed));

#define BT_LMP_CLKOFFSET_REQ 5

#define BT_LMP_CLKOFFSET_RSP 6
struct bt_lmp_clkoffset_rsp {
  u16 offset;
} __attribute__((packed));

#define BT_LMP_DETACH 7
struct bt_lmp_detach {
  u8 error;
} __attribute__((packed));

#define BT_LMP_AU_RAND 11
struct bt_lmp_au_rand {
  u8 number[16];
} __attribute__((packed));

#define BT_LMP_SRES 12
struct bt_lmp_sres {
  u8 response[4];
} __attribute__((packed));

#define BT_LMP_ENCRYPTION_MODE_REQ 15
struct bt_lmp_encryption_mode_req {
  u8 mode;
} __attribute__((packed));

#define BT_LMP_ENCRYPTION_KEY_SIZE_REQ 16
struct bt_lmp_encryption_key_size_req {
  u8 key_size;
} __attribute__((packed));

#define BT_LMP_START_ENCRYPTION_REQ 17
struct bt_lmp_start_encryption_req {
  u8 number[16];
} __attribute__((packed));

#define BT_LMP_STOP_ENCRYPTION_REQ 18

#define BT_LMP_SWITCH_REQ 19
struct bt_lmp_switch_req {
  u32 instant;
} __attribute__((packed));

#define BT_LMP_UNSNIFF_REQ 24

#define BT_LMP_MAX_POWER 33

#define BT_LMP_MIN_POWER 34

#define BT_LMP_AUTO_RATE 35

#define BT_LMP_PREFERRED_RATE 36
struct bt_lmp_preferred_rate {
  u8 rate;
} __attribute__((packed));

#define BT_LMP_VERSION_REQ 37
struct bt_lmp_version_req {
  u8 version;
  u16 company;
  u16 subversion;
} __attribute__((packed));

#define BT_LMP_VERSION_RES 38
struct bt_lmp_version_res {
  u8 version;
  u16 company;
  u16 subversion;
} __attribute__((packed));

#define BT_LMP_FEATURES_REQ 39
struct bt_lmp_features_req {
  u8 features[8];
} __attribute__((packed));

#define BT_LMP_FEATURES_RES 40
struct bt_lmp_features_res {
  u8 features[8];
} __attribute__((packed));

#define BT_LMP_MAX_SLOT 45
struct bt_lmp_max_slot {
  u8 slots;
} __attribute__((packed));

#define BT_LMP_MAX_SLOT_REQ 46
struct bt_lmp_max_slot_req {
  u8 slots;
} __attribute__((packed));

#define BT_LMP_TIMING_ACCURACY_REQ 47

#define BT_LMP_TIMING_ACCURACY_RES 48
struct bt_lmp_timing_accuracy_res {
  u8 drift;
  u8 jitter;
} __attribute__((packed));

#define BT_LMP_SETUP_COMPLETE 49

#define BT_LMP_USE_SEMI_PERMANENT_KEY 50

#define BT_LMP_HOST_CONNECTION_REQ 51

#define BT_LMP_SLOT_OFFSET 52
struct bt_lmp_slot_offset {
  u16 offset;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_LMP_PAGE_SCAN_MODE_REQ 54
struct bt_lmp_page_scan_mode_req {
  u8 scheme;
  u8 settings;
} __attribute__((packed));

#define BT_LMP_TEST_ACTIVATE 56

#define BT_LMP_ENCRYPTION_KEY_SIZE_MASK_REQ 58

#define BT_LMP_SET_AFH 60
struct bt_lmp_set_afh {
  u32 instant;
  u8 mode;
  u8 map[10];
} __attribute__((packed));

#define BT_LMP_ENCAPSULATED_HEADER 61
struct bt_lmp_encapsulated_header {
  u8 major;
  u8 minor;
  u8 length;
} __attribute__((packed));

#define BT_LMP_ENCAPSULATED_PAYLOAD 62
struct bt_lmp_encapsulated_payload {
  u8 data[16];
} __attribute__((packed));

#define BT_LMP_SIMPLE_PAIRING_CONFIRM 63
struct bt_lmp_simple_pairing_confirm {
  u8 value[16];
} __attribute__((packed));

#define BT_LMP_SIMPLE_PAIRING_NUMBER 64
struct bt_lmp_simple_pairing_number {
  u8 value[16];
} __attribute__((packed));

#define BT_LMP_DHKEY_CHECK 65
struct bt_lmp_dhkey_check {
  u8 value[16];
} __attribute__((packed));

#define BT_LMP_PAUSE_ENCRYPTION_AES_REQ 66

#define BT_LMP_ACCEPTED_EXT LMP_ESC4(1)
struct bt_lmp_accepted_ext {
  u8 escape;
  u8 opcode;
} __attribute__((packed));

#define BT_LMP_NOT_ACCEPTED_EXT LMP_ESC4(2)
struct bt_lmp_not_accepted_ext {
  u8 escape;
  u8 opcode;
  u8 error;
} __attribute__((packed));

#define BT_LMP_FEATURES_REQ_EXT LMP_ESC4(3)
struct bt_lmp_features_req_ext {
  u8 page;
  u8 max_page;
  u8 features[8];
} __attribute__((packed));

#define BT_LMP_FEATURES_RES_EXT LMP_ESC4(4)
struct bt_lmp_features_res_ext {
  u8 page;
  u8 max_page;
  u8 features[8];
} __attribute__((packed));

#define BT_LMP_PACKET_TYPE_TABLE_REQ LMP_ESC4(11)
struct bt_lmp_packet_type_table_req {
  u8 table;
} __attribute__((packed));

#define BT_LMP_CHANNEL_CLASSIFICATION_REQ LMP_ESC4(16)
struct bt_lmp_channel_classification_req {
  u8 mode;
  u16 min_interval;
  u16 max_interval;
} __attribute__((packed));

#define BT_LMP_CHANNEL_CLASSIFICATION LMP_ESC4(17)
struct bt_lmp_channel_classification {
  u8 classification[10];
} __attribute__((packed));

#define BT_LMP_PAUSE_ENCRYPTION_REQ LMP_ESC4(23)

#define BT_LMP_RESUME_ENCRYPTION_REQ LMP_ESC4(24)

#define BT_LMP_IO_CAPABILITY_REQ LMP_ESC4(25)
struct bt_lmp_io_capability_req {
  u8 capability;
  u8 oob_data;
  u8 authentication;
} __attribute__((packed));

#define BT_LMP_IO_CAPABILITY_RES LMP_ESC4(26)
struct bt_lmp_io_capability_res {
  u8 capability;
  u8 oob_data;
  u8 authentication;
} __attribute__((packed));

#define BT_LMP_NUMERIC_COMPARISON_FAILED LMP_ESC(27)

#define BT_LMP_PASSKEY_FAILED LMP_ESC4(28)

#define BT_LMP_OOB_FAILED LMP_ESC(29)

#define BT_LMP_POWER_CONTROL_REQ LMP_ESC4(31)
struct bt_lmp_power_control_req {
  u8 request;
} __attribute__((packed));

#define BT_LMP_POWER_CONTROL_RES LMP_ESC4(32)
struct bt_lmp_power_control_res {
  u8 response;
} __attribute__((packed));

#define BT_LMP_PING_REQ LMP_ESC4(33)

#define BT_LMP_PING_RES LMP_ESC4(34)

#define BT_H4_CMD_PKT 0x01
#define BT_H4_ACL_PKT 0x02
#define BT_H4_SCO_PKT 0x03
#define BT_H4_EVT_PKT 0x04
#define BT_H4_ISO_PKT 0x05

struct bt_hci_cmd_hdr {
  u16 opcode;
  u8 plen;
} __attribute__((packed));

struct bt_hci_acl_hdr {
  u16 handle;
  u16 dlen;
  u8 data[];
} __attribute__((packed));

struct bt_hci_sco_hdr {
  u16 handle;
  u8 dlen;
} __attribute__((packed));

struct bt_hci_iso_hdr {
  u16 handle;
  u16 dlen;
  u8 data[];
} __attribute__((packed));

struct bt_hci_iso_data_start {
  u16 sn;
  u16 slen;
  u8 data[];
} __attribute__((packed));

struct bt_hci_evt_hdr {
  u8 evt;
  u8 plen;
} __attribute__((packed));

#define BT_HCI_CMD_NOP 0x0000

#define BT_HCI_CMD_INQUIRY 0x0401
struct bt_hci_cmd_inquiry {
  u8 lap[3];
  u8 length;
  u8 num_resp;
} __attribute__((packed));

#define BT_HCI_CMD_INQUIRY_CANCEL 0x0402

#define BT_HCI_CMD_PERIODIC_INQUIRY 0x0403
struct bt_hci_cmd_periodic_inquiry {
  u16 max_period;
  u16 min_period;
  u8 lap[3];
  u8 length;
  u8 num_resp;
} __attribute__((packed));

#define BT_HCI_CMD_EXIT_PERIODIC_INQUIRY 0x0404

#define BT_HCI_CMD_CREATE_CONN 0x0405
struct bt_hci_cmd_create_conn {
  u8 bdaddr[6];
  u16 pkt_type;
  u8 pscan_rep_mode;
  u8 pscan_mode;
  u16 clock_offset;
  u8 role_switch;
} __attribute__((packed));

#define BT_HCI_CMD_DISCONNECT 0x0406
struct bt_hci_cmd_disconnect {
  u16 handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_CMD_ADD_SCO_CONN 0x0407
struct bt_hci_cmd_add_sco_conn {
  u16 handle;
  u16 pkt_type;
} __attribute__((packed));

#define BT_HCI_CMD_CREATE_CONN_CANCEL 0x0408
struct bt_hci_cmd_create_conn_cancel {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_ACCEPT_CONN_REQUEST 0x0409
struct bt_hci_cmd_accept_conn_request {
  u8 bdaddr[6];
  u8 role;
} __attribute__((packed));

#define BT_HCI_CMD_REJECT_CONN_REQUEST 0x040a
struct bt_hci_cmd_reject_conn_request {
  u8 bdaddr[6];
  u8 reason;
} __attribute__((packed));

#define BT_HCI_CMD_LINK_KEY_REQUEST_REPLY 0x040b
struct bt_hci_cmd_link_key_request_reply {
  u8 bdaddr[6];
  u8 link_key[16];
} __attribute__((packed));
struct bt_hci_rsp_link_key_request_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LINK_KEY_REQUEST_NEG_REPLY 0x040c
struct bt_hci_cmd_link_key_request_neg_reply {
  u8 bdaddr[6];
} __attribute__((packed));
struct bt_hci_rsp_link_key_request_neg_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_PIN_CODE_REQUEST_REPLY 0x040d
struct bt_hci_cmd_pin_code_request_reply {
  u8 bdaddr[6];
  u8 pin_len;
  u8 pin_code[16];
} __attribute__((packed));

#define BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY 0x040e
struct bt_hci_cmd_pin_code_request_neg_reply {
  u8 bdaddr[6];
} __attribute__((packed));
struct bt_hci_rsp_pin_code_request_neg_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_CHANGE_CONN_PKT_TYPE 0x040f
struct bt_hci_cmd_change_conn_pkt_type {
  u16 handle;
  u16 pkt_type;
} __attribute__((packed));

#define BT_HCI_CMD_AUTH_REQUESTED 0x0411
struct bt_hci_cmd_auth_requested {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_SET_CONN_ENCRYPT 0x0413
struct bt_hci_cmd_set_conn_encrypt {
  u16 handle;
  u8 encr_mode;
} __attribute__((packed));

#define BT_HCI_CMD_CHANGE_CONN_LINK_KEY 0x0415
struct bt_hci_cmd_change_conn_link_key {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LINK_KEY_SELECTION 0x0417
struct bt_hci_cmd_link_key_selection {
  u8 key_flag;
} __attribute__((packed));

#define BT_HCI_CMD_REMOTE_NAME_REQUEST 0x0419
struct bt_hci_cmd_remote_name_request {
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_mode;
  u16 clock_offset;
} __attribute__((packed));

#define BT_HCI_CMD_REMOTE_NAME_REQUEST_CANCEL 0x041a
struct bt_hci_cmd_remote_name_request_cancel {
  u8 bdaddr[6];
} __attribute__((packed));
struct bt_hci_rsp_remote_name_request_cancel {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_READ_REMOTE_FEATURES 0x041b
struct bt_hci_cmd_read_remote_features {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_REMOTE_EXT_FEATURES 0x041c
struct bt_hci_cmd_read_remote_ext_features {
  u16 handle;
  u8 page;
} __attribute__((packed));

#define BT_HCI_CMD_READ_REMOTE_VERSION 0x041d
struct bt_hci_cmd_read_remote_version {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_CLOCK_OFFSET 0x041f
struct bt_hci_cmd_read_clock_offset {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LMP_HANDLE 0x0420
struct bt_hci_cmd_read_lmp_handle {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_lmp_handle {
  u8 status;
  u16 handle;
  u8 lmp_handle;
  u32 reserved;
} __attribute__((packed));

#define BT_HCI_CMD_SETUP_SYNC_CONN 0x0428
struct bt_hci_cmd_setup_sync_conn {
  u16 handle;
  u32 tx_bandwidth;
  u32 rx_bandwidth;
  u16 max_latency;
  u16 voice_setting;
  u8 retrans_effort;
  u16 pkt_type;
} __attribute__((packed));

#define BT_HCI_CMD_ACCEPT_SYNC_CONN_REQUEST 0x0429
struct bt_hci_cmd_accept_sync_conn_request {
  u8 bdaddr[6];
  u32 tx_bandwidth;
  u32 rx_bandwidth;
  u16 max_latency;
  u16 voice_setting;
  u8 retrans_effort;
  u16 pkt_type;
} __attribute__((packed));

#define BT_HCI_CMD_REJECT_SYNC_CONN_REQUEST 0x042a
struct bt_hci_cmd_reject_sync_conn_request {
  u8 bdaddr[6];
  u8 reason;
} __attribute__((packed));

#define BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY 0x042b
struct bt_hci_cmd_io_capability_request_reply {
  u8 bdaddr[6];
  u8 capability;
  u8 oob_data;
  u8 authentication;
} __attribute__((packed));
struct bt_hci_rsp_io_capability_request_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY 0x042c
struct bt_hci_cmd_user_confirm_request_reply {
  u8 bdaddr[6];
} __attribute__((packed));
struct bt_hci_rsp_user_confirm_request_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_USER_CONFIRM_REQUEST_NEG_REPLY 0x042d
struct bt_hci_cmd_user_confirm_request_neg_reply {
  u8 bdaddr[6];
} __attribute__((packed));
struct bt_hci_rsp_user_confirm_request_neg_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_USER_PASSKEY_REQUEST_REPLY 0x042e
struct bt_hci_cmd_user_passkey_request_reply {
  u8 bdaddr[6];
  u32 passkey;
} __attribute__((packed));

#define BT_HCI_CMD_USER_PASSKEY_REQUEST_NEG_REPLY 0x042f
struct bt_hci_cmd_user_passkey_request_neg_reply {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_REPLY 0x0430
struct bt_hci_cmd_remote_oob_data_request_reply {
  u8 bdaddr[6];
  u8 hash[16];
  u8 randomizer[16];
} __attribute__((packed));

#define BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_NEG_REPLY 0x0433
struct bt_hci_cmd_remote_oob_data_request_neg_reply {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_IO_CAPABILITY_REQUEST_NEG_REPLY 0x0434
struct bt_hci_cmd_io_capability_request_neg_reply {
  u8 bdaddr[6];
  u8 reason;
} __attribute__((packed));
struct bt_hci_rsp_io_capability_request_neg_reply {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_CREATE_PHY_LINK 0x0435
struct bt_hci_cmd_create_phy_link {
  u8 phy_handle;
  u8 key_len;
  u8 key_type;
} __attribute__((packed));

#define BT_HCI_CMD_ACCEPT_PHY_LINK 0x0436
struct bt_hci_cmd_accept_phy_link {
  u8 phy_handle;
  u8 key_len;
  u8 key_type;
} __attribute__((packed));

#define BT_HCI_CMD_DISCONN_PHY_LINK 0x0437
struct bt_hci_cmd_disconn_phy_link {
  u8 phy_handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_CMD_CREATE_LOGIC_LINK 0x0438
struct bt_hci_cmd_create_logic_link {
  u8 phy_handle;
  u8 tx_flow_spec[16];
  u8 rx_flow_spec[16];
} __attribute__((packed));

#define BT_HCI_CMD_ACCEPT_LOGIC_LINK 0x0439
struct bt_hci_cmd_accept_logic_link {
  u8 phy_handle;
  u8 tx_flow_spec[16];
  u8 rx_flow_spec[16];
} __attribute__((packed));

#define BT_HCI_CMD_DISCONN_LOGIC_LINK 0x043a
struct bt_hci_cmd_disconn_logic_link {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LOGIC_LINK_CANCEL 0x043b
struct bt_hci_cmd_logic_link_cancel {
  u8 phy_handle;
  u8 flow_spec;
} __attribute__((packed));
struct bt_hci_rsp_logic_link_cancel {
  u8 status;
  u8 phy_handle;
  u8 flow_spec;
} __attribute__((packed));

#define BT_HCI_CMD_FLOW_SPEC_MODIFY 0x043c
struct bt_hci_cmd_flow_spec_modify {
  u16 handle;
  u8 tx_flow_spec[16];
  u8 rx_flow_spec[16];
} __attribute__((packed));

#define BT_HCI_CMD_ENHANCED_SETUP_SYNC_CONN 0x043d
struct bt_hci_cmd_enhanced_setup_sync_conn {
  u16 handle;
  u32 tx_bandwidth;
  u32 rx_bandwidth;
  u8 tx_coding_format[5];
  u8 rx_coding_format[5];
  u16 tx_codec_frame_size;
  u16 rx_codec_frame_size;
  u32 input_bandwidth;
  u32 output_bandwidth;
  u8 input_coding_format[5];
  u8 output_coding_format[5];
  u16 input_coded_data_size;
  u16 output_coded_data_size;
  u8 input_pcm_data_format;
  u8 output_pcm_data_format;
  u8 input_pcm_msb_position;
  u8 output_pcm_msb_position;
  u8 input_data_path;
  u8 output_data_path;
  u8 input_unit_size;
  u8 output_unit_size;
  u16 max_latency;
  u16 pkt_type;
  u8 retrans_effort;
} __attribute__((packed));

#define BT_HCI_CMD_ENHANCED_ACCEPT_SYNC_CONN_REQUEST 0x043e
struct bt_hci_cmd_enhanced_accept_sync_conn_request {
  u8 bdaddr[6];
  u32 tx_bandwidth;
  u32 rx_bandwidth;
  u8 tx_coding_format[5];
  u8 rx_coding_format[5];
  u16 tx_codec_frame_size;
  u16 rx_codec_frame_size;
  u32 input_bandwidth;
  u32 output_bandwidth;
  u8 input_coding_format[5];
  u8 output_coding_format[5];
  u16 input_coded_data_size;
  u16 output_coded_data_size;
  u8 input_pcm_data_format;
  u8 output_pcm_data_format;
  u8 input_pcm_msb_position;
  u8 output_pcm_msb_position;
  u8 input_data_path;
  u8 output_data_path;
  u8 input_unit_size;
  u8 output_unit_size;
  u16 max_latency;
  u16 pkt_type;
  u8 retrans_effort;
} __attribute__((packed));

#define BT_HCI_CMD_TRUNCATED_PAGE 0x043f
struct bt_hci_cmd_truncated_page {
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u16 clock_offset;
} __attribute__((packed));

#define BT_HCI_CMD_TRUNCATED_PAGE_CANCEL 0x0440
struct bt_hci_cmd_truncated_page_cancel {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST 0x0441
struct bt_hci_cmd_set_peripheral_broadcast {
  u8 enable;
  u8 lt_addr;
  u8 lpo_allowed;
  u16 pkt_type;
  u16 min_interval;
  u16 max_interval;
  u16 timeout;
} __attribute__((packed));
struct bt_hci_rsp_set_peripheral_broadcast {
  u8 status;
  u8 lt_addr;
  u16 interval;
} __attribute__((packed));

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_RECEIVE 0x0442
struct bt_hci_cmd_set_peripheral_broadcast_receive {
  u8 enable;
  u8 bdaddr[6];
  u8 lt_addr;
  u16 interval;
  u32 offset;
  u32 instant;
  u16 timeout;
  u8 accuracy;
  u8 skip;
  u16 pkt_type;
  u8 map[10];
} __attribute__((packed));
struct bt_hci_rsp_set_peripheral_broadcast_receive {
  u8 status;
  u8 bdaddr[6];
  u8 lt_addr;
} __attribute__((packed));

#define BT_HCI_CMD_START_SYNC_TRAIN 0x0443

#define BT_HCI_CMD_RECEIVE_SYNC_TRAIN 0x0444
struct bt_hci_cmd_receive_sync_train {
  u8 bdaddr[6];
  u16 timeout;
  u16 window;
  u16 interval;
} __attribute__((packed));

#define BT_HCI_CMD_REMOTE_OOB_EXT_DATA_REQUEST_REPLY 0x0445
struct bt_hci_cmd_remote_oob_ext_data_request_reply {
  u8 bdaddr[6];
  u8 hash192[16];
  u8 randomizer192[16];
  u8 hash256[16];
  u8 randomizer256[16];
} __attribute__((packed));

#define BT_HCI_CMD_HOLD_MODE 0x0801
struct bt_hci_cmd_hold_mode {
  u16 handle;
  u16 max_interval;
  u16 min_interval;
} __attribute__((packed));

#define BT_HCI_CMD_SNIFF_MODE 0x0803
struct bt_hci_cmd_sniff_mode {
  u16 handle;
  u16 max_interval;
  u16 min_interval;
  u16 attempt;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_EXIT_SNIFF_MODE 0x0804
struct bt_hci_cmd_exit_sniff_mode {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_PARK_STATE 0x0805
struct bt_hci_cmd_park_state {
  u16 handle;
  u16 max_interval;
  u16 min_interval;
} __attribute__((packed));

#define BT_HCI_CMD_EXIT_PARK_STATE 0x0806
struct bt_hci_cmd_exit_park_state {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_QOS_SETUP 0x0807
struct bt_hci_cmd_qos_setup {
  u16 handle;
  u8 flags;
  u8 service_type;
  u32 token_rate;
  u32 peak_bandwidth;
  u32 latency;
  u32 delay_variation;
} __attribute__((packed));

#define BT_HCI_CMD_ROLE_DISCOVERY 0x0809
struct bt_hci_cmd_role_discovery {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_role_discovery {
  u8 status;
  u16 handle;
  u8 role;
} __attribute__((packed));

#define BT_HCI_CMD_SWITCH_ROLE 0x080b
struct bt_hci_cmd_switch_role {
  u8 bdaddr[6];
  u8 role;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LINK_POLICY 0x080c
struct bt_hci_cmd_read_link_policy {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_link_policy {
  u8 status;
  u16 handle;
  u16 policy;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_LINK_POLICY 0x080d
struct bt_hci_cmd_write_link_policy {
  u16 handle;
  u16 policy;
} __attribute__((packed));
struct bt_hci_rsp_write_link_policy {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_DEFAULT_LINK_POLICY 0x080e
struct bt_hci_rsp_read_default_link_policy {
  u8 status;
  u16 policy;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_DEFAULT_LINK_POLICY 0x080f
struct bt_hci_cmd_write_default_link_policy {
  u16 policy;
} __attribute__((packed));

#define BT_HCI_CMD_FLOW_SPEC 0x0810
struct bt_hci_cmd_flow_spec {
  u16 handle;
  u8 flags;
  u8 direction;
  u8 service_type;
  u32 token_rate;
  u32 token_bucket_size;
  u32 peak_bandwidth;
  u32 access_latency;
} __attribute__((packed));

#define BT_HCI_CMD_SNIFF_SUBRATING 0x0811
struct bt_hci_cmd_sniff_subrating {
  u16 handle;
  u16 max_latency;
  u16 min_remote_timeout;
  u16 min_local_timeout;
} __attribute__((packed));
struct bt_hci_rsp_sniff_subrating {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_SET_EVENT_MASK 0x0c01
struct bt_hci_cmd_set_event_mask {
  u8 mask[8];
} __attribute__((packed));

#define BT_HCI_CMD_RESET 0x0c03

#define BT_HCI_CMD_SET_EVENT_FILTER 0x0c05
struct bt_hci_cmd_set_event_filter {
  u8 type;
  u8 cond_type;
  u8 cond[0];
} __attribute__((packed));

#define BT_HCI_CMD_FLUSH 0x0c08
struct bt_hci_cmd_flush {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_flush {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_PIN_TYPE 0x0c09
struct bt_hci_rsp_read_pin_type {
  u8 status;
  u8 pin_type;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_PIN_TYPE 0x0c0a
struct bt_hci_cmd_write_pin_type {
  u8 pin_type;
} __attribute__((packed));

#define BT_HCI_CMD_CREATE_NEW_UNIT_KEY 0x0c0b

#define BT_HCI_CMD_READ_STORED_LINK_KEY 0x0c0d
struct bt_hci_cmd_read_stored_link_key {
  u8 bdaddr[6];
  u8 read_all;
} __attribute__((packed));
struct bt_hci_rsp_read_stored_link_key {
  u8 status;
  u16 max_num_keys;
  u16 num_keys;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_STORED_LINK_KEY 0x0c11
struct bt_hci_cmd_write_stored_link_key {
  u8 num_keys;
} __attribute__((packed));
struct bt_hci_rsp_write_stored_link_key {
  u8 status;
  u8 num_keys;
} __attribute__((packed));

#define BT_HCI_CMD_DELETE_STORED_LINK_KEY 0x0c12
struct bt_hci_cmd_delete_stored_link_key {
  u8 bdaddr[6];
  u8 delete_all;
} __attribute__((packed));
struct bt_hci_rsp_delete_stored_link_key {
  u8 status;
  u16 num_keys;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_LOCAL_NAME 0x0c13
struct bt_hci_cmd_write_local_name {
  u8 name[248];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_NAME 0x0c14
struct bt_hci_rsp_read_local_name {
  u8 status;
  char name[248];
} __attribute__((packed));

#define BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT 0x0c15
struct bt_hci_rsp_read_conn_accept_timeout {
  u8 status;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_CONN_ACCEPT_TIMEOUT 0x0c16
struct bt_hci_cmd_write_conn_accept_timeout {
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_READ_PAGE_TIMEOUT 0x0c17
struct bt_hci_rsp_read_page_timeout {
  u8 status;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_PAGE_TIMEOUT 0x0c18
struct bt_hci_cmd_write_page_timeout {
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_READ_SCAN_ENABLE 0x0c19
struct bt_hci_rsp_read_scan_enable {
  u8 status;
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_SCAN_ENABLE 0x0c1a
struct bt_hci_cmd_write_scan_enable {
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_READ_PAGE_SCAN_ACTIVITY 0x0c1b
struct bt_hci_rsp_read_page_scan_activity {
  u8 status;
  u16 interval;
  u16 window;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY 0x0c1c
struct bt_hci_cmd_write_page_scan_activity {
  u16 interval;
  u16 window;
} __attribute__((packed));

#define BT_HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY 0x0c1d
struct bt_hci_rsp_read_inquiry_scan_activity {
  u8 status;
  u16 interval;
  u16 window;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY 0x0c1e
struct bt_hci_cmd_write_inquiry_scan_activity {
  u16 interval;
  u16 window;
} __attribute__((packed));

#define BT_HCI_CMD_READ_AUTH_ENABLE 0x0c1f
struct bt_hci_rsp_read_auth_enable {
  u8 status;
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_AUTH_ENABLE 0x0c20
struct bt_hci_cmd_write_auth_enable {
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_READ_ENCRYPT_MODE 0x0c21
struct bt_hci_rsp_read_encrypt_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_ENCRYPT_MODE 0x0c22
struct bt_hci_cmd_write_encrypt_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_CLASS_OF_DEV 0x0c23
struct bt_hci_rsp_read_class_of_dev {
  u8 status;
  u8 dev_class[3];
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_CLASS_OF_DEV 0x0c24
struct bt_hci_cmd_write_class_of_dev {
  u8 dev_class[3];
} __attribute__((packed));

#define BT_HCI_CMD_READ_VOICE_SETTING 0x0c25
struct bt_hci_rsp_read_voice_setting {
  u8 status;
  u16 setting;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_VOICE_SETTING 0x0c26
struct bt_hci_cmd_write_voice_setting {
  u16 setting;
} __attribute__((packed));

#define BT_HCI_CMD_READ_AUTO_FLUSH_TIMEOUT 0x0c27
struct bt_hci_cmd_read_auto_flush_timeout {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_auto_flush_timeout {
  u8 status;
  u16 handle;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_AUTO_FLUSH_TIMEOUT 0x0c28
struct bt_hci_cmd_write_auto_flush_timeout {
  u16 handle;
  u16 timeout;
} __attribute__((packed));
struct bt_hci_rsp_write_auto_flush_timeout {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_NUM_BROADCAST_RETRANS 0x0c29
struct bt_hci_rsp_read_num_broadcast_retrans {
  u8 status;
  u8 num_retrans;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_NUM_BROADCAST_RETRANS 0x0c2a
struct bt_hci_cmd_write_num_broadcast_retrans {
  u8 num_retrans;
} __attribute__((packed));

#define BT_HCI_CMD_READ_HOLD_MODE_ACTIVITY 0x0c2b
struct bt_hci_rsp_read_hold_mode_activity {
  u8 status;
  u8 activity;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_HOLD_MODE_ACTIVITY 0x0c2c
struct bt_hci_cmd_write_hold_mode_activity {
  u8 activity;
} __attribute__((packed));

#define BT_HCI_CMD_READ_TX_POWER 0x0c2d
struct bt_hci_cmd_read_tx_power {
  u16 handle;
  u8 type;
} __attribute__((packed));
struct bt_hci_rsp_read_tx_power {
  u8 status;
  u16 handle;
  int8_t level;
} __attribute__((packed));

#define BT_HCI_CMD_READ_SYNC_FLOW_CONTROL 0x0c2e
struct bt_hci_rsp_read_sync_flow_control {
  u8 status;
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_SYNC_FLOW_CONTROL 0x0c2f
struct bt_hci_cmd_write_sync_flow_control {
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_SET_HOST_FLOW_CONTROL 0x0c31
struct bt_hci_cmd_set_host_flow_control {
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_HOST_BUFFER_SIZE 0x0c33
struct bt_hci_cmd_host_buffer_size {
  u16 acl_mtu;
  u8 sco_mtu;
  u16 acl_max_pkt;
  u16 sco_max_pkt;
} __attribute__((packed));

#define BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS 0x0c35
struct bt_hci_cmd_host_num_completed_packets {
  u8 num_handles;
  u16 handle;
  u16 count;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LINK_SUPV_TIMEOUT 0x0c36
struct bt_hci_cmd_read_link_supv_timeout {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_link_supv_timeout {
  u8 status;
  u16 handle;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_LINK_SUPV_TIMEOUT 0x0c37
struct bt_hci_cmd_write_link_supv_timeout {
  u16 handle;
  u16 timeout;
} __attribute__((packed));
struct bt_hci_rsp_write_link_supv_timeout {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_NUM_SUPPORTED_IAC 0x0c38
struct bt_hci_rsp_read_num_supported_iac {
  u8 status;
  u8 num_iac;
} __attribute__((packed));

#define BT_HCI_CMD_READ_CURRENT_IAC_LAP 0x0c39
struct bt_hci_rsp_read_current_iac_lap {
  u8 status;
  u8 num_iac;
  u8 iac_lap[0];
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_CURRENT_IAC_LAP 0x0c3a
struct bt_hci_cmd_write_current_iac_lap {
  u8 num_iac;
  u8 iac_lap[0];
} __attribute__((packed));

#define BT_HCI_CMD_READ_PAGE_SCAN_PERIOD_MODE 0x0c3b
struct bt_hci_rsp_read_page_scan_period_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_PAGE_SCAN_PERIOD_MODE 0x0c3c
struct bt_hci_cmd_write_page_scan_period_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_PAGE_SCAN_MODE 0x0c3d
struct bt_hci_rsp_read_page_scan_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_PAGE_SCAN_MODE 0x0c3e
struct bt_hci_cmd_write_page_scan_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_SET_AFH_HOST_CLASSIFICATION 0x0c3f
struct bt_hci_cmd_set_afh_host_classification {
  u8 map[10];
} __attribute__((packed));

#define BT_HCI_CMD_READ_INQUIRY_SCAN_TYPE 0x0c42
struct bt_hci_rsp_read_inquiry_scan_type {
  u8 status;
  u8 type;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_INQUIRY_SCAN_TYPE 0x0c43
struct bt_hci_cmd_write_inquiry_scan_type {
  u8 type;
} __attribute__((packed));

#define BT_HCI_CMD_READ_INQUIRY_MODE 0x0c44
struct bt_hci_rsp_read_inquiry_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_INQUIRY_MODE 0x0c45
struct bt_hci_cmd_write_inquiry_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_PAGE_SCAN_TYPE 0x0c46
struct bt_hci_rsp_read_page_scan_type {
  u8 status;
  u8 type;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_PAGE_SCAN_TYPE 0x0c47
struct bt_hci_cmd_write_page_scan_type {
  u8 type;
} __attribute__((packed));

#define BT_HCI_CMD_READ_AFH_ASSESSMENT_MODE 0x0c48
struct bt_hci_rsp_read_afh_assessment_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_AFH_ASSESSMENT_MODE 0x0c49
struct bt_hci_cmd_write_afh_assessment_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_EXT_INQUIRY_RESPONSE 0x0c51
struct bt_hci_rsp_read_ext_inquiry_response {
  u8 status;
  u8 fec;
  u8 data[240];
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE 0x0c52
struct bt_hci_cmd_write_ext_inquiry_response {
  u8 fec;
  u8 data[240];
} __attribute__((packed));

#define BT_HCI_CMD_REFRESH_ENCRYPT_KEY 0x0c53
struct bt_hci_cmd_refresh_encrypt_key {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_SIMPLE_PAIRING_MODE 0x0c55
struct bt_hci_rsp_read_simple_pairing_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE 0x0c56
struct bt_hci_cmd_write_simple_pairing_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_OOB_DATA 0x0c57
struct bt_hci_rsp_read_local_oob_data {
  u8 status;
  u8 hash[16];
  u8 randomizer[16];
} __attribute__((packed));

#define BT_HCI_CMD_READ_INQUIRY_RESP_TX_POWER 0x0c58
struct bt_hci_rsp_read_inquiry_resp_tx_power {
  u8 status;
  int8_t level;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_INQUIRY_TX_POWER 0x0c59
struct bt_hci_cmd_write_inquiry_tx_power {
  int8_t level;
} __attribute__((packed));

#define BT_HCI_CMD_READ_ERRONEOUS_REPORTING 0x0c5a
struct bt_hci_rsp_read_erroneous_reporting {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_ERRONEOUS_REPORTING 0x0c5b
struct bt_hci_cmd_write_erroneous_reporting {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_ENHANCED_FLUSH 0x0c5f
struct bt_hci_cmd_enhanced_flush {
  u16 handle;
  u8 type;
} __attribute__((packed));

#define BT_HCI_CMD_SEND_KEYPRESS_NOTIFY 0x0c60
struct bt_hci_cmd_send_keypress_notify {
  u8 bdaddr[6];
  u8 type;
} __attribute__((packed));
struct bt_hci_rsp_send_keypress_notify {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_SET_EVENT_MASK_PAGE2 0x0c63
struct bt_hci_cmd_set_event_mask_page2 {
  u8 mask[8];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCATION_DATA 0x0c64
struct bt_hci_rsp_read_location_data {
  u8 status;
  u8 domain_aware;
  u8 domain[2];
  u8 domain_options;
  u8 options;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_LOCATION_DATA 0x0c65
struct bt_hci_cmd_write_location_data {
  u8 domain_aware;
  u8 domain[2];
  u8 domain_options;
  u8 options;
} __attribute__((packed));

#define BT_HCI_CMD_READ_FLOW_CONTROL_MODE 0x0c66
struct bt_hci_rsp_read_flow_control_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_FLOW_CONTROL_MODE 0x0c67
struct bt_hci_cmd_write_flow_control_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_ENHANCED_TX_POWER 0x0c68
struct bt_hci_cmd_read_enhanced_tx_power {
  u16 handle;
  u8 type;
} __attribute__((packed));
struct bt_hci_rsp_read_enhanced_tx_power {
  u8 status;
  u16 handle;
  int8_t level_gfsk;
  int8_t level_dqpsk;
  int8_t level_8dpsk;
} __attribute__((packed));

#define BT_HCI_CMD_SHORT_RANGE_MODE 0x0c6b
struct bt_hci_cmd_short_range_mode {
  u8 phy_handle;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LE_HOST_SUPPORTED 0x0c6c
struct bt_hci_rsp_read_le_host_supported {
  u8 status;
  u8 supported;
  u8 simultaneous;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED 0x0c6d
struct bt_hci_cmd_write_le_host_supported {
  u8 supported;
  u8 simultaneous;
} __attribute__((packed));

#define BT_HCI_CMD_SET_RESERVED_LT_ADDR 0x0c74
struct bt_hci_cmd_set_reserved_lt_addr {
  u8 lt_addr;
} __attribute__((packed));
struct bt_hci_rsp_set_reserved_lt_addr {
  u8 status;
  u8 lt_addr;
} __attribute__((packed));

#define BT_HCI_CMD_DELETE_RESERVED_LT_ADDR 0x0c75
struct bt_hci_cmd_delete_reserved_lt_addr {
  u8 lt_addr;
} __attribute__((packed));
struct bt_hci_rsp_delete_reserved_lt_addr {
  u8 status;
  u8 lt_addr;
} __attribute__((packed));

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_DATA 0x0c76
struct bt_hci_cmd_set_peripheral_broadcast_data {
  u8 lt_addr;
  u8 fragment;
  u8 length;
} __attribute__((packed));
struct bt_hci_rsp_set_peripheral_broadcast_data {
  u8 status;
  u8 lt_addr;
} __attribute__((packed));

#define BT_HCI_CMD_READ_SYNC_TRAIN_PARAMS 0x0c77
struct bt_hci_rsp_read_sync_train_params {
  u8 status;
  u16 interval;
  u32 timeout;
  u8 service_data;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_SYNC_TRAIN_PARAMS 0x0c78
struct bt_hci_cmd_write_sync_train_params {
  u16 min_interval;
  u16 max_interval;
  u32 timeout;
  u8 service_data;
} __attribute__((packed));
struct bt_hci_rsp_write_sync_train_params {
  u8 status;
  u16 interval;
} __attribute__((packed));

#define BT_HCI_CMD_READ_SECURE_CONN_SUPPORT 0x0c79
struct bt_hci_rsp_read_secure_conn_support {
  u8 status;
  u8 support;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_SECURE_CONN_SUPPORT 0x0c7a
struct bt_hci_cmd_write_secure_conn_support {
  u8 support;
} __attribute__((packed));

#define BT_HCI_CMD_READ_AUTH_PAYLOAD_TIMEOUT 0x0c7b
struct bt_hci_cmd_read_auth_payload_timeout {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_auth_payload_timeout {
  u8 status;
  u16 handle;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_AUTH_PAYLOAD_TIMEOUT 0x0c7c
struct bt_hci_cmd_write_auth_payload_timeout {
  u16 handle;
  u16 timeout;
} __attribute__((packed));
struct bt_hci_rsp_write_auth_payload_timeout {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_OOB_EXT_DATA 0x0c7d
struct bt_hci_rsp_read_local_oob_ext_data {
  u8 status;
  u8 hash192[16];
  u8 randomizer192[16];
  u8 hash256[16];
  u8 randomizer256[16];
} __attribute__((packed));

#define BT_HCI_CMD_READ_EXT_PAGE_TIMEOUT 0x0c7e
struct bt_hci_rsp_read_ext_page_timeout {
  u8 status;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_EXT_PAGE_TIMEOUT 0x0c7f
struct bt_hci_cmd_write_ext_page_timeout {
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_READ_EXT_INQUIRY_LENGTH 0x0c80
struct bt_hci_rsp_read_ext_inquiry_length {
  u8 status;
  u16 interval;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_LENGTH 0x0c81
struct bt_hci_cmd_write_ext_inquiry_length {
  u16 interval;
} __attribute__((packed));

#define BT_HCI_CMD_CONFIG_DATA_PATH 0x0c83
#define BT_HCI_BIT_CONFIG_DATA_PATH BT_HCI_CMD_BIT(45, 5)
struct bt_hci_cmd_config_data_path {
  u8 dir;
  u8 id;
  u8 vnd_config_len;
  u8 vnd_config[0];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_VERSION 0x1001
struct bt_hci_rsp_read_local_version {
  u8 status;
  u8 hci_ver;
  u16 hci_rev;
  u8 lmp_ver;
  u16 manufacturer;
  u16 lmp_subver;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_COMMANDS 0x1002
struct bt_hci_rsp_read_local_commands {
  u8 status;
  u8 commands[64];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_FEATURES 0x1003
struct bt_hci_rsp_read_local_features {
  u8 status;
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_EXT_FEATURES 0x1004
struct bt_hci_cmd_read_local_ext_features {
  u8 page;
} __attribute__((packed));
struct bt_hci_rsp_read_local_ext_features {
  u8 status;
  u8 page;
  u8 max_page;
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_CMD_READ_BUFFER_SIZE 0x1005
struct bt_hci_rsp_read_buffer_size {
  u8 status;
  u16 acl_mtu;
  u8 sco_mtu;
  u16 acl_max_pkt;
  u16 sco_max_pkt;
} __attribute__((packed));

#define BT_HCI_CMD_READ_COUNTRY_CODE 0x1007
struct bt_hci_rsp_read_country_code {
  u8 status;
  u8 code;
} __attribute__((packed));

#define BT_HCI_CMD_READ_BD_ADDR 0x1009
struct bt_hci_rsp_read_bd_addr {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_READ_DATA_BLOCK_SIZE 0x100a
struct bt_hci_rsp_read_data_block_size {
  u8 status;
  u16 max_acl_len;
  u16 block_len;
  u16 num_blocks;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_CODECS 0x100b
struct bt_hci_rsp_read_local_codecs {
  u8 status;
  u8 num_codecs;
  u8 codec[0];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_PAIRING_OPTIONS 0x100c
struct bt_hci_rsp_read_local_pairing_options {
  u8 status;
  u8 pairing_options;
  u8 max_key_size;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_CODECS_V2 0x100d
#define BT_HCI_BIT_READ_LOCAL_CODECS_V2 BT_HCI_CMD_BIT(45, 2)
#define BT_HCI_LOCAL_CODEC_BREDR_ACL BIT(0)
#define BT_HCI_LOCAL_CODEC_BREDR_SCO BIT(1)
#define BT_HCI_LOCAL_CODEC_LE_CIS BIT(2)
#define BT_HCI_LOCAL_CODEC_LE_BIS BIT(3)

struct bt_hci_vnd_codec {
  u8 id;
  u16 cid;
  u16 vid;
  u8 transport;
} __attribute__((packed));

struct bt_hci_codec {
  u8 id;
  u8 transport;
} __attribute__((packed));

struct bt_hci_rsp_read_local_codecs_v2 {
  u8 status;
  u8 num_codecs;
  struct bt_hci_codec codec[0];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_CODEC_CAPS 0x100e
#define BT_HCI_BIT_READ_LOCAL_CODEC_CAPS BT_HCI_CMD_BIT(45, 3)
struct bt_hci_cmd_read_local_codec_caps {
  struct bt_hci_vnd_codec codec;
  u8 dir;
} __attribute__((packed));

struct bt_hci_codec_caps {
  u8 len;
  u8 data[0];
} __attribute__((packed));

struct bt_hci_rsp_read_local_codec_caps {
  u8 status;
  u8 num;
  struct bt_hci_codec_caps caps[0];
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_CTRL_DELAY 0x100f
#define BT_HCI_BIT_READ_LOCAL_CTRL_DELAY BT_HCI_CMD_BIT(45, 4)
struct bt_hci_cmd_read_local_ctrl_delay {
  struct bt_hci_vnd_codec codec;
  u8 dir;
  u8 codec_cfg_len;
  u8 codec_cfg[0];
} __attribute__((packed));

struct bt_hci_rsp_read_local_ctrl_delay {
  u8 status;
  u8 min_delay[3];
  u8 max_delay[3];
} __attribute__((packed));

#define BT_HCI_CMD_READ_FAILED_CONTACT_COUNTER 0x1401
struct bt_hci_cmd_read_failed_contact_counter {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_failed_contact_counter {
  u8 status;
  u16 handle;
  u16 counter;
} __attribute__((packed));

#define BT_HCI_CMD_RESET_FAILED_CONTACT_COUNTER 0x1402
struct bt_hci_cmd_reset_failed_contact_counter {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_reset_failed_contact_counter {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LINK_QUALITY 0x1403
struct bt_hci_cmd_read_link_quality {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_link_quality {
  u8 status;
  u16 handle;
  u8 link_quality;
} __attribute__((packed));

#define BT_HCI_CMD_READ_RSSI 0x1405
struct bt_hci_cmd_read_rssi {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_rssi {
  u8 status;
  u16 handle;
  int8_t rssi;
} __attribute__((packed));

#define BT_HCI_CMD_READ_AFH_CHANNEL_MAP 0x1406
struct bt_hci_cmd_read_afh_channel_map {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_afh_channel_map {
  u8 status;
  u16 handle;
  u8 mode;
  u8 map[10];
} __attribute__((packed));

#define BT_HCI_CMD_READ_CLOCK 0x1407
struct bt_hci_cmd_read_clock {
  u16 handle;
  u8 type;
} __attribute__((packed));
struct bt_hci_rsp_read_clock {
  u8 status;
  u16 handle;
  u32 clock;
  u16 accuracy;
} __attribute__((packed));

#define BT_HCI_CMD_READ_ENCRYPT_KEY_SIZE 0x1408
struct bt_hci_cmd_read_encrypt_key_size {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_read_encrypt_key_size {
  u8 status;
  u16 handle;
  u8 key_size;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_AMP_INFO 0x1409
struct bt_hci_rsp_read_local_amp_info {
  u8 status;
  u8 amp_status;
  u32 total_bw;
  u32 max_bw;
  u32 min_latency;
  u32 max_pdu;
  u8 amp_type;
  u16 pal_cap;
  u16 max_assoc_len;
  u32 max_flush_to;
  u32 be_flush_to;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOCAL_AMP_ASSOC 0x140a
struct bt_hci_cmd_read_local_amp_assoc {
  u8 phy_handle;
  u16 len_so_far;
  u16 max_assoc_len;
} __attribute__((packed));
struct bt_hci_rsp_read_local_amp_assoc {
  u8 status;
  u8 phy_handle;
  u16 remain_assoc_len;
  u8 assoc_fragment[248];
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_REMOTE_AMP_ASSOC 0x140b
struct bt_hci_cmd_write_remote_amp_assoc {
  u8 phy_handle;
  u16 len_so_far;
  u16 remain_assoc_len;
  u8 assoc_fragment[248];
} __attribute__((packed));
struct bt_hci_rsp_write_remote_amp_assoc {
  u8 status;
  u8 phy_handle;
} __attribute__((packed));

#define BT_HCI_CMD_GET_MWS_TRANSPORT_CONFIG 0x140c
struct bt_hci_rsp_get_mws_transport_config {
  u8 status;
  u8 num_transports;
  u8 transport[0];
} __attribute__((packed));

#define BT_HCI_CMD_SET_TRIGGERED_CLOCK_CAPTURE 0x140d
struct bt_hci_cmd_set_triggered_clock_capture {
  u16 handle;
  u8 enable;
  u8 type;
  u8 lpo_allowed;
  u8 num_filter;
} __attribute__((packed));

#define BT_HCI_CMD_READ_LOOPBACK_MODE 0x1801
struct bt_hci_rsp_read_loopback_mode {
  u8 status;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_WRITE_LOOPBACK_MODE 0x1802
struct bt_hci_cmd_write_loopback_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_ENABLE_DUT_MODE 0x1803

#define BT_HCI_CMD_WRITE_SSP_DEBUG_MODE 0x1804
struct bt_hci_cmd_write_ssp_debug_mode {
  u8 mode;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EVENT_MASK 0x2001
struct bt_hci_cmd_le_set_event_mask {
  u8 mask[8];
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE 0x2002
struct bt_hci_rsp_le_read_buffer_size {
  u8 status;
  u16 le_mtu;
  u8 le_max_pkt;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_LOCAL_FEATURES 0x2003
struct bt_hci_rsp_le_read_local_features {
  u8 status;
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_RANDOM_ADDRESS 0x2005
struct bt_hci_cmd_le_set_random_address {
  u8 addr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_ADV_PARAMETERS 0x2006
struct bt_hci_cmd_le_set_adv_parameters {
  u16 min_interval;
  u16 max_interval;
  u8 type;
  u8 own_addr_type;
  u8 direct_addr_type;
  u8 direct_addr[6];
  u8 channel_map;
  u8 filter_policy;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_ADV_TX_POWER 0x2007
struct bt_hci_rsp_le_read_adv_tx_power {
  u8 status;
  int8_t level;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_ADV_DATA 0x2008
struct bt_hci_cmd_le_set_adv_data {
  u8 len;
  u8 data[31];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_SCAN_RSP_DATA 0x2009
struct bt_hci_cmd_le_set_scan_rsp_data {
  u8 len;
  u8 data[31];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_ADV_ENABLE 0x200a
struct bt_hci_cmd_le_set_adv_enable {
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_SCAN_PARAMETERS 0x200b
struct bt_hci_cmd_le_set_scan_parameters {
  u8 type;
  u16 interval;
  u16 window;
  u8 own_addr_type;
  u8 filter_policy;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_SCAN_ENABLE 0x200c
struct bt_hci_cmd_le_set_scan_enable {
  u8 enable;
  u8 filter_dup;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CREATE_CONN 0x200d
struct bt_hci_cmd_le_create_conn {
  u16 scan_interval;
  u16 scan_window;
  u8 filter_policy;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u8 own_addr_type;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CREATE_CONN_CANCEL 0x200e

#define BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE 0x200f
struct bt_hci_rsp_le_read_accept_list_size {
  u8 status;
  u8 size;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CLEAR_ACCEPT_LIST 0x2010

#define BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST 0x2011
struct bt_hci_cmd_le_add_to_accept_list {
  u8 addr_type;
  u8 addr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_REMOVE_FROM_ACCEPT_LIST 0x2012
struct bt_hci_cmd_le_remove_from_accept_list {
  u8 addr_type;
  u8 addr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_CONN_UPDATE 0x2013
struct bt_hci_cmd_le_conn_update {
  u16 handle;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_HOST_CLASSIFICATION 0x2014
struct bt_hci_cmd_le_set_host_classification {
  u8 map[5];
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_CHANNEL_MAP 0x2015
struct bt_hci_cmd_le_read_channel_map {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_le_read_channel_map {
  u8 status;
  u16 handle;
  u8 map[5];
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_REMOTE_FEATURES 0x2016
struct bt_hci_cmd_le_read_remote_features {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_ENCRYPT 0x2017
struct bt_hci_cmd_le_encrypt {
  u8 key[16];
  u8 plaintext[16];
} __attribute__((packed));
struct bt_hci_rsp_le_encrypt {
  u8 status;
  u8 data[16];
} __attribute__((packed));

#define BT_HCI_CMD_LE_RAND 0x2018
struct bt_hci_rsp_le_rand {
  u8 status;
  u64 number;
} __attribute__((packed));

#define BT_HCI_CMD_LE_START_ENCRYPT 0x2019
struct bt_hci_cmd_le_start_encrypt {
  u16 handle;
  u64 rand;
  u16 ediv;
  u8 ltk[16];
} __attribute__((packed));

#define BT_HCI_CMD_LE_LTK_REQ_REPLY 0x201a
struct bt_hci_cmd_le_ltk_req_reply {
  u16 handle;
  u8 ltk[16];
} __attribute__((packed));
struct bt_hci_rsp_le_ltk_req_reply {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_LTK_REQ_NEG_REPLY 0x201b
struct bt_hci_cmd_le_ltk_req_neg_reply {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_le_ltk_req_neg_reply {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_SUPPORTED_STATES 0x201c
struct bt_hci_rsp_le_read_supported_states {
  u8 status;
  u8 states[8];
} __attribute__((packed));

#define BT_HCI_CMD_LE_RECEIVER_TEST 0x201d
struct bt_hci_cmd_le_receiver_test {
  u8 frequency;
} __attribute__((packed));

#define BT_HCI_CMD_LE_TRANSMITTER_TEST 0x201e
struct bt_hci_cmd_le_transmitter_test {
  u8 frequency;
  u8 data_len;
  u8 payload;
} __attribute__((packed));

#define BT_HCI_CMD_LE_TEST_END 0x201f
struct bt_hci_rsp_le_test_end {
  u8 status;
  u16 num_packets;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CONN_PARAM_REQ_REPLY 0x2020
struct bt_hci_cmd_le_conn_param_req_reply {
  u16 handle;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} __attribute__((packed));
struct bt_hci_rsp_le_conn_param_req_reply {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CONN_PARAM_REQ_NEG_REPLY 0x2021
struct bt_hci_cmd_le_conn_param_req_neg_reply {
  u16 handle;
  u8 reason;
} __attribute__((packed));
struct bt_hci_rsp_le_conn_param_req_neg_reply {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_DATA_LENGTH 0x2022
struct bt_hci_cmd_le_set_data_length {
  u16 handle;
  u16 tx_len;
  u16 tx_time;
} __attribute__((packed));
struct bt_hci_rsp_le_set_data_length {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_DEFAULT_DATA_LENGTH 0x2023
struct bt_hci_rsp_le_read_default_data_length {
  u8 status;
  u16 tx_len;
  u16 tx_time;
} __attribute__((packed));

#define BT_HCI_CMD_LE_WRITE_DEFAULT_DATA_LENGTH 0x2024
struct bt_hci_cmd_le_write_default_data_length {
  u16 tx_len;
  u16 tx_time;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_LOCAL_PK256 0x2025

#define BT_HCI_CMD_LE_GENERATE_DHKEY 0x2026
struct bt_hci_cmd_le_generate_dhkey {
  u8 remote_pk256[64];
} __attribute__((packed));

#define BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST 0x2027
struct bt_hci_cmd_le_add_to_resolv_list {
  u8 addr_type;
  u8 addr[6];
  u8 peer_irk[16];
  u8 local_irk[16];
} __attribute__((packed));

#define BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST 0x2028
struct bt_hci_cmd_le_remove_from_resolv_list {
  u8 addr_type;
  u8 addr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_CLEAR_RESOLV_LIST 0x2029

#define BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE 0x202a
struct bt_hci_rsp_le_read_resolv_list_size {
  u8 status;
  u8 size;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_PEER_RESOLV_ADDR 0x202b
struct bt_hci_cmd_le_read_peer_resolv_addr {
  u8 addr_type;
  u8 addr[6];
} __attribute__((packed));
struct bt_hci_rsp_le_read_peer_resolv_addr {
  u8 status;
  u8 addr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_LOCAL_RESOLV_ADDR 0x202c
struct bt_hci_cmd_le_read_local_resolv_addr {
  u8 addr_type;
  u8 addr[6];
} __attribute__((packed));
struct bt_hci_rsp_le_read_local_resolv_addr {
  u8 status;
  u8 addr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_RESOLV_ENABLE 0x202d
struct bt_hci_cmd_le_set_resolv_enable {
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_RESOLV_TIMEOUT 0x202e
struct bt_hci_cmd_le_set_resolv_timeout {
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH 0x202f
struct bt_hci_rsp_le_read_max_data_length {
  u8 status;
  u16 max_tx_len;
  u16 max_tx_time;
  u16 max_rx_len;
  u16 max_rx_time;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_PHY 0x2030
struct bt_hci_cmd_le_read_phy {
  u16 handle;
} __attribute__((packed));
struct bt_hci_rsp_le_read_phy {
  u8 status;
  u16 handle;
  u8 tx_phy;
  u8 rx_phy;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_DEFAULT_PHY 0x2031
struct bt_hci_cmd_le_set_default_phy {
  u8 all_phys;
  u8 tx_phys;
  u8 rx_phys;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_PHY 0x2032
struct bt_hci_cmd_le_set_phy {
  u16 handle;
  u8 all_phys;
  u8 tx_phys;
  u8 rx_phys;
  u16 phy_opts;
} __attribute__((packed));

#define BT_HCI_CMD_LE_ENHANCED_RECEIVER_TEST 0x2033
struct bt_hci_cmd_le_enhanced_receiver_test {
  u8 rx_channel;
  u8 phy;
  u8 modulation_index;
} __attribute__((packed));

#define BT_HCI_CMD_LE_ENHANCED_TRANSMITTER_TEST 0x2034
struct bt_hci_cmd_le_enhanced_transmitter_test {
  u8 tx_channel;
  u8 data_len;
  u8 payload;
  u8 phy;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_ADV_SET_RAND_ADDR 0x2035
struct bt_hci_cmd_le_set_adv_set_rand_addr {
  u8 handle;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS 0x2036
struct bt_hci_cmd_le_set_ext_adv_params {
  u8 handle;
  u16 evt_properties;
  u8 min_interval[3];
  u8 max_interval[3];
  u8 channel_map;
  u8 own_addr_type;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u8 filter_policy;
  u8 tx_power;
  u8 primary_phy;
  u8 secondary_max_skip;
  u8 secondary_phy;
  u8 sid;
  u8 notif_enable;
} __attribute__((packed));
struct bt_hci_rsp_le_set_ext_adv_params {
  u8 status;
  u8 tx_power;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EXT_ADV_DATA 0x2037
struct bt_hci_cmd_le_set_ext_adv_data {
  u8 handle;
  u8 operation;
  u8 fragment_preference;
  u8 data_len;
  u8 data[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA 0x2038
struct bt_hci_cmd_le_set_ext_scan_rsp_data {
  u8 handle;
  u8 operation;
  u8 fragment_preference;
  u8 data_len;
  u8 data[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE 0x2039
struct bt_hci_cmd_le_set_ext_adv_enable {
  u8 enable;
  u8 num_of_sets;
} __attribute__((packed));
struct bt_hci_cmd_ext_adv_set {
  u8 handle;
  u16 duration;
  u8 max_events;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_MAX_ADV_DATA_LEN 0x203a
struct bt_hci_rsp_le_read_max_adv_data_len {
  u8 status;
  u16 max_len;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_NUM_SUPPORTED_ADV_SETS 0x203b
struct bt_hci_rsp_le_read_num_supported_adv_sets {
  u8 status;
  u8 num_of_sets;
} __attribute__((packed));

#define BT_HCI_CMD_LE_REMOVE_ADV_SET 0x203c
struct bt_hci_cmd_le_remove_adv_set {
  u8 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CLEAR_ADV_SETS 0x203d

#define BT_HCI_CMD_LE_SET_PA_PARAMS 0x203e
struct bt_hci_cmd_le_set_pa_params {
  u8 handle;
  u16 min_interval;
  u16 max_interval;
  u16 properties;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_PA_DATA 0x203f
struct bt_hci_cmd_le_set_pa_data {
  u8 handle;
  u8 operation;
  u8 data_len;
  u8 data[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_PA_ENABLE 0x2040
struct bt_hci_cmd_le_set_pa_enable {
  u8 enable;
  u8 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS 0x2041
struct bt_hci_cmd_le_set_ext_scan_params {
  u8 own_addr_type;
  u8 filter_policy;
  u8 num_phys;
  u8 data[0];
} __attribute__((packed));
struct bt_hci_le_scan_phy {
  u8 type;
  u16 interval;
  u16 window;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE 0x2042
struct bt_hci_cmd_le_set_ext_scan_enable {
  u8 enable;
  u8 filter_dup;
  u16 duration;
  u16 period;
} __attribute__((packed));

#define BT_HCI_CMD_LE_EXT_CREATE_CONN 0x2043
struct bt_hci_cmd_le_ext_create_conn {
  u8 filter_policy;
  u8 own_addr_type;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u8 phys;
  u8 data[0];
} __attribute__((packed));
struct bt_hci_le_ext_create_conn {
  u16 scan_interval;
  u16 scan_window;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} __attribute__((packed));

#define BT_HCI_CMD_LE_PA_CREATE_SYNC 0x2044
struct bt_hci_cmd_le_pa_create_sync {
  u8 options;
  u8 sid;
  u8 addr_type;
  u8 addr[6];
  u16 skip;
  u16 sync_timeout;
  u8 sync_cte_type;
} __attribute__((packed));

#define BT_HCI_CMD_LE_PA_CREATE_SYNC_CANCEL 0x2045

#define BT_HCI_CMD_LE_PA_TERM_SYNC 0x2046
struct bt_hci_cmd_le_pa_term_sync {
  u16 sync_handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_ADD_DEV_PA_LIST 0x2047
struct bt_hci_cmd_le_add_dev_pa_list {
  u8 addr_type;
  u8 addr[6];
  u8 sid;
} __attribute__((packed));

#define BT_HCI_CMD_LE_REMOVE_DEV_PA_LIST 0x2048
struct bt_hci_cmd_le_remove_dev_pa_list {
  u8 addr_type;
  u8 addr[6];
  u8 sid;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CLEAR_PA_LIST 0x2049

#define BT_HCI_CMD_LE_READ_PA_LIST_SIZE 0x204a
struct bt_hci_rsp_le_read_dev_pa_list_size {
  u8 status;
  u8 list_size;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_TX_POWER 0x204b
struct bt_hci_rsp_le_read_tx_power {
  u8 status;
  int8_t min_tx_power;
  int8_t max_tx_power;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_RF_PATH_COMPENSATION 0x204c
struct bt_hci_rsp_le_read_rf_path_comp {
  u8 status;
  u16 rf_tx_path_comp;
  u16 rf_rx_path_comp;
} __attribute__((packed));

#define BT_HCI_CMD_LE_WRITE_RF_PATH_COMPENSATION 0x204d
struct bt_hci_cmd_le_write_rf_path_comp {
  u16 rf_tx_path_comp;
  u16 rf_rx_path_comp;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_PRIV_MODE 0x204e
struct bt_hci_cmd_le_set_priv_mode {
  u8 peer_id_addr_type;
  u8 peer_id_addr[6];
  u8 priv_mode;
} __attribute__((packed));

#define BT_HCI_CMD_LE_RECEIVER_TEST_V3 0x204f
struct bt_hci_cmd_le_receiver_test_v3 {
  u8 rx_chan;
  u8 phy;
  u8 mod_index;
  u8 cte_len;
  u8 cte_type;
  u8 duration;
  u8 num_antenna_id;
  u8 antenna_ids[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_TX_TEST_V3 0x2050
struct bt_hci_cmd_le_tx_test_v3 {
  u8 chan;
  u8 data_len;
  u8 payload;
  u8 phy;
  u8 cte_len;
  u8 cte_type;
  u8 duration;
  u8 num_antenna_id;
  u8 antenna_ids[0];
} __attribute__((packed));

#define BT_HCI_CMD_SET_PA_REC_ENABLE 0x2059
struct bt_hci_cmd_set_pa_rec_enable {
  u16 sync_handle;
  u8 enable;
} __attribute__((packed));

#define BT_HCI_CMD_PERIODIC_SYNC_TRANS 0x205a
struct bt_hci_cmd_periodic_sync_trans {
  u16 handle;
  u16 service_data;
  u16 sync_handle;
} __attribute__((packed));

#define BT_HCI_CMD_PA_SET_INFO_TRANS 0x205b
struct bt_hci_cmd_pa_set_info_trans {
  u16 handle;
  u16 service_data;
  u16 adv_handle;
} __attribute__((packed));

#define BT_HCI_CMD_PA_SYNC_TRANS_PARAMS 0x205c
struct bt_hci_cmd_pa_sync_trans_params {
  u16 handle;
  u8 mode;
  u16 skip;
  u16 sync_timeout;
  u8 cte_type;
} __attribute__((packed));

#define BT_HCI_CMD_DEFAULT_PA_SYNC_TRANS_PARAMS 0x205d
struct bt_hci_cmd_default_pa_sync_trans_params {
  u8 mode;
  u16 skip;
  u16 sync_timeout;
  u8 cte_type;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE_V2 0x2060
#define BT_HCI_BIT_LE_READ_BUFFER_SIZE_V2 BT_HCI_CMD_BIT(41, 5)
struct bt_hci_rsp_le_read_buffer_size_v2 {
  u8 status;
  u16 acl_mtu;
  u8 acl_max_pkt;
  u16 iso_mtu;
  u8 iso_max_pkt;
} __attribute__((packed));

#define BT_HCI_CMD_LE_READ_ISO_TX_SYNC 0x2061
#define BT_HCI_BIT_LE_READ_ISO_TX_SYNC BT_HCI_CMD_BIT(41, 6)
struct bt_hci_cmd_le_read_iso_tx_sync {
  u16 handle;
} __attribute__((packed));

struct bt_hci_rsp_le_read_iso_tx_sync {
  u8 status;
  u16 handle;
  u16 seq;
  u32 timestamp;
  u8 offset[3];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_CIG_PARAMS 0x2062
#define BT_HCI_BIT_LE_SET_CIG_PARAMS BT_HCI_CMD_BIT(41, 7)
struct bt_hci_cis_params {
  u8 cis_id;
  u16 c_sdu;
  u16 p_sdu;
  u8 c_phy;
  u8 p_phy;
  u8 c_rtn;
  u8 p_rtn;
} __attribute__((packed));

struct bt_hci_cmd_le_set_cig_params {
  u8 cig_id;
  u8 c_interval[3];
  u8 p_interval[3];
  u8 sca;
  u8 packing;
  u8 framing;
  u16 c_latency;
  u16 p_latency;
  u8 num_cis;
  struct bt_hci_cis_params cis[0];
} __attribute__((packed));

struct bt_hci_rsp_le_set_cig_params {
  u8 status;
  u8 cig_id;
  u8 num_handles;
  u16 handle[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_SET_CIG_PARAMS_TEST 0x2063
#define BT_HCI_BIT_LE_SET_CIG_PARAMS_TEST BT_HCI_CMD_BIT(42, 0)
struct bt_hci_cis_params_test {
  u8 cis_id;
  u8 nse;
  u16 c_sdu;
  u16 p_sdu;
  u16 c_pdu;
  u16 p_pdu;
  u8 c_phy;
  u8 p_phy;
  u8 c_bn;
  u8 p_bn;
} __attribute__((packed));

struct bt_hci_cmd_le_set_cig_params_test {
  u8 cig_id;
  u8 c_interval[3];
  u8 p_interval[3];
  u8 c_ft;
  u8 p_ft;
  u16 iso_interval;
  u8 sca;
  u8 packing;
  u8 framing;
  u8 num_cis;
  struct bt_hci_cis_params_test cis[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_CREATE_CIS 0x2064
#define BT_HCI_BIT_LE_CREATE_CIS BT_HCI_CMD_BIT(42, 1)
struct bt_hci_cis {
  u16 cis_handle;
  u16 acl_handle;
} __attribute__((packed));

struct bt_hci_cmd_le_create_cis {
  u8 num_cis;
  struct bt_hci_cis cis[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_REMOVE_CIG 0x2065
#define BT_HCI_BIT_LE_REMOVE_CIG BT_HCI_CMD_BIT(42, 2)
struct bt_hci_cmd_le_remove_cig {
  u8 cig_id;
} __attribute__((packed));

struct bt_hci_rsp_le_remove_cig {
  u8 status;
  u8 cig_id;
} __attribute__((packed));

#define BT_HCI_CMD_LE_ACCEPT_CIS 0x2066
#define BT_HCI_BIT_LE_ACCEPT_CIS BT_HCI_CMD_BIT(42, 3)
struct bt_hci_cmd_le_accept_cis {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_REJECT_CIS 0x2067
#define BT_HCI_BIT_LE_REJECT_CIS BT_HCI_CMD_BIT(42, 4)
struct bt_hci_cmd_le_reject_cis {
  u16 handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CREATE_BIG 0x2068
#define BT_HCI_BIT_LE_CREATE_BIG BT_HCI_CMD_BIT(42, 5)
struct bt_hci_bis {
  u8 sdu_interval[3];
  u16 sdu;
  u16 latency;
  u8 rtn;
  u8 phy;
  u8 packing;
  u8 framing;
  u8 encryption;
  u8 bcode[16];
} __attribute__((packed));

struct bt_hci_cmd_le_create_big {
  u8 handle;
  u8 adv_handle;
  u8 num_bis;
  struct bt_hci_bis bis;
} __attribute__((packed));

#define BT_HCI_CMD_LE_CREATE_BIG_TEST 0x2069
#define BT_HCI_BIT_LE_CREATE_BIG_TEST BT_HCI_CMD_BIT(42, 6)
struct bt_hci_bis_test {
  u8 sdu_interval[3];
  u16 iso_interval;
  u8 nse;
  u16 sdu;
  u8 pdu;
  u8 phy;
  u8 packing;
  u8 framing;
  u8 bn;
  u8 irc;
  u8 pto;
  u8 adv_handle;
  u8 encryption;
  u8 bcode[16];
} __attribute__((packed));

struct bt_hci_cmd_le_create_big_test {
  u8 big_id;
  u8 adv_handle;
  u8 num_bis;
  struct bt_hci_bis_test bis[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_TERM_BIG 0x206a
#define BT_HCI_BIT_LE_TERM_BIG BT_HCI_CMD_BIT(42, 7)
struct bt_hci_cmd_le_term_big {
  u8 handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_CMD_LE_BIG_CREATE_SYNC 0x206b
#define BT_HCI_BIT_LE_BIG_CREATE_SYNC BT_HCI_CMD_BIT(43, 0)
struct bt_hci_bis_sync {
  u8 index;
} __attribute__((packed));

struct bt_hci_cmd_le_big_create_sync {
  u8 handle;
  u16 sync_handle;
  u8 encryption;
  u8 bcode[16];
  u8 mse;
  u16 timeout;
  u8 num_bis;
  struct bt_hci_bis_sync bis[0];
} __attribute__((packed));

#define BT_HCI_CMD_LE_BIG_TERM_SYNC 0x206c
#define BT_HCI_BIT_LE_BIG_TERM_SYNC BT_HCI_CMD_BIT(43, 1)
struct bt_hci_cmd_le_big_term_sync {
  u8 handle;
} __attribute__((packed));

struct bt_hci_rsp_le_big_term_sync {
  u8 status;
  u8 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_REQ_PEER_SCA 0x206d
#define BT_HCI_BIT_LE_REQ_PEER_SCA BT_HCI_CMD_BIT(43, 2)
struct bt_hci_cmd_le_req_peer_sca {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_SETUP_ISO_PATH 0x206e
#define BT_HCI_BIT_LE_SETUP_ISO_PATH BT_HCI_CMD_BIT(43, 3)
struct bt_hci_cmd_le_setup_iso_path {
  u16 handle;
  u8 direction;
  u8 path;
  u8 codec;
  u16 codec_cid;
  u16 codec_vid;
  u8 delay[3];
  u8 codec_cfg_len;
  u8 codec_cfg[0];
} __attribute__((packed));

struct bt_hci_rsp_le_setup_iso_path {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_CMD_LE_REMOVE_ISO_PATH 0x206f
#define BT_HCI_BIT_LE_REMOVE_ISO_PATH BT_HCI_CMD_BIT(43, 4)
struct bt_hci_cmd_le_remove_iso_path {
  u16 handle;
  u8 direction;
} __attribute__((packed));

#define BT_HCI_CMD_LE_ISO_TX_TEST 0x2070
#define BT_HCI_BIT_LE_ISO_TX_TEST BT_HCI_CMD_BIT(43, 5)

#define BT_HCI_CMD_LE_ISO_RX_TEST 0x2071
#define BT_HCI_BIT_LE_ISO_RX_TEST BT_HCI_CMD_BIT(43, 6)

#define BT_HCI_CMD_LE_ISO_READ_TEST_COUNTER 0x2072
#define BT_HCI_BIT_LE_ISO_READ_TEST_COUNTER BT_HCI_CMD_BIT(43, 7)

#define BT_HCI_CMD_LE_ISO_TEST_END 0x2073
#define BT_HCI_BIT_LE_ISO_TEST_END BT_HCI_CMD_BIT(44, 0)

#define BT_HCI_CMD_LE_SET_HOST_FEATURE 0x2074
#define BT_HCI_BIT_LE_SET_HOST_FEATURE BT_HCI_CMD_BIT(44, 1)
struct bt_hci_cmd_le_set_host_feature {
  u8 bit_number;
  u8 bit_value;
} __attribute__((packed));

#define BT_HCI_EVT_INQUIRY_COMPLETE 0x01
struct bt_hci_evt_inquiry_complete {
  u8 status;
} __attribute__((packed));

#define BT_HCI_EVT_INQUIRY_RESULT 0x02
struct bt_hci_evt_inquiry_result {
  u8 num_resp;
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_period_mode;
  u8 pscan_mode;
  u8 dev_class[3];
  u16 clock_offset;
} __attribute__((packed));

#define BT_HCI_EVT_CONN_COMPLETE 0x03
struct bt_hci_evt_conn_complete {
  u8 status;
  u16 handle;
  u8 bdaddr[6];
  u8 link_type;
  u8 encr_mode;
} __attribute__((packed));

#define BT_HCI_EVT_CONN_REQUEST 0x04
struct bt_hci_evt_conn_request {
  u8 bdaddr[6];
  u8 dev_class[3];
  u8 link_type;
} __attribute__((packed));

#define BT_HCI_EVT_DISCONNECT_COMPLETE 0x05
struct bt_hci_evt_disconnect_complete {
  u8 status;
  u16 handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_EVT_AUTH_COMPLETE 0x06
struct bt_hci_evt_auth_complete {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE 0x07
struct bt_hci_evt_remote_name_request_complete {
  u8 status;
  u8 bdaddr[6];
  u8 name[248];
} __attribute__((packed));

#define BT_HCI_EVT_ENCRYPT_CHANGE 0x08
struct bt_hci_evt_encrypt_change {
  u8 status;
  u16 handle;
  u8 encr_mode;
} __attribute__((packed));

#define BT_HCI_EVT_CHANGE_CONN_LINK_KEY_COMPLETE 0x09
struct bt_hci_evt_change_conn_link_key_complete {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_LINK_KEY_TYPE_CHANGED 0x0a
struct bt_hci_evt_link_key_type_changed {
  u8 status;
  u16 handle;
  u8 key_flag;
} __attribute__((packed));

#define BT_HCI_EVT_REMOTE_FEATURES_COMPLETE 0x0b
struct bt_hci_evt_remote_features_complete {
  u8 status;
  u16 handle;
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_EVT_REMOTE_VERSION_COMPLETE 0x0c
struct bt_hci_evt_remote_version_complete {
  u8 status;
  u16 handle;
  u8 lmp_ver;
  u16 manufacturer;
  u16 lmp_subver;
} __attribute__((packed));

#define BT_HCI_EVT_QOS_SETUP_COMPLETE 0x0d
struct bt_hci_evt_qos_setup_complete {
  u8 status;
  u16 handle;
  u8 flags;
  u8 service_type;
  u32 token_rate;
  u32 peak_bandwidth;
  u32 latency;
  u32 delay_variation;
} __attribute__((packed));

#define BT_HCI_EVT_CMD_COMPLETE 0x0e
struct bt_hci_evt_cmd_complete {
  u8 ncmd;
  u16 opcode;
  u8 param[0];
} __attribute__((packed));

#define BT_HCI_EVT_CMD_STATUS 0x0f
struct bt_hci_evt_cmd_status {
  u8 status;
  u8 ncmd;
  u16 opcode;
} __attribute__((packed));

#define BT_HCI_EVT_HARDWARE_ERROR 0x10
struct bt_hci_evt_hardware_error {
  u8 code;
} __attribute__((packed));

#define BT_HCI_EVT_FLUSH_OCCURRED 0x11
struct bt_hci_evt_flush_occurred {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_ROLE_CHANGE 0x12
struct bt_hci_evt_role_change {
  u8 status;
  u8 bdaddr[6];
  u8 role;
} __attribute__((packed));

#define BT_HCI_EVT_NUM_COMPLETED_PACKETS 0x13
struct bt_hci_evt_num_completed_packets {
  u8 num_handles;
  u16 handle;
  u16 count;
} __attribute__((packed));

#define BT_HCI_EVT_MODE_CHANGE 0x14
struct bt_hci_evt_mode_change {
  u8 status;
  u16 handle;
  u8 mode;
  u16 interval;
} __attribute__((packed));

#define BT_HCI_EVT_RETURN_LINK_KEYS 0x15
struct bt_hci_evt_return_link_keys {
  u8 num_keys;
  u8 keys[0];
} __attribute__((packed));

#define BT_HCI_EVT_PIN_CODE_REQUEST 0x16
struct bt_hci_evt_pin_code_request {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_LINK_KEY_REQUEST 0x17
struct bt_hci_evt_link_key_request {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_LINK_KEY_NOTIFY 0x18
struct bt_hci_evt_link_key_notify {
  u8 bdaddr[6];
  u8 link_key[16];
  u8 key_type;
} __attribute__((packed));

#define BT_HCI_EVT_LOOPBACK_COMMAND 0x19

#define BT_HCI_EVT_DATA_BUFFER_OVERFLOW 0x1a
struct bt_hci_evt_data_buffer_overflow {
  u8 link_type;
} __attribute__((packed));

#define BT_HCI_EVT_MAX_SLOTS_CHANGE 0x1b
struct bt_hci_evt_max_slots_change {
  u16 handle;
  u8 max_slots;
} __attribute__((packed));

#define BT_HCI_EVT_CLOCK_OFFSET_COMPLETE 0x1c
struct bt_hci_evt_clock_offset_complete {
  u8 status;
  u16 handle;
  u16 clock_offset;
} __attribute__((packed));

#define BT_HCI_EVT_CONN_PKT_TYPE_CHANGED 0x1d
struct bt_hci_evt_conn_pkt_type_changed {
  u8 status;
  u16 handle;
  u16 pkt_type;
} __attribute__((packed));

#define BT_HCI_EVT_QOS_VIOLATION 0x1e
struct bt_hci_evt_qos_violation {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_PSCAN_MODE_CHANGE 0x1f
struct bt_hci_evt_pscan_mode_change {
  u8 bdaddr[6];
  u8 pscan_mode;
} __attribute__((packed));

#define BT_HCI_EVT_PSCAN_REP_MODE_CHANGE 0x20
struct bt_hci_evt_pscan_rep_mode_change {
  u8 bdaddr[6];
  u8 pscan_rep_mode;
} __attribute__((packed));

#define BT_HCI_EVT_FLOW_SPEC_COMPLETE 0x21
struct bt_hci_evt_flow_spec_complete {
  u8 status;
  u16 handle;
  u8 flags;
  u8 direction;
  u8 service_type;
  u32 token_rate;
  u32 token_bucket_size;
  u32 peak_bandwidth;
  u32 access_latency;
} __attribute__((packed));

#define BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI 0x22
struct bt_hci_evt_inquiry_result_with_rssi {
  u8 num_resp;
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_period_mode;
  u8 dev_class[3];
  u16 clock_offset;
  int8_t rssi;
} __attribute__((packed));

#define BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE 0x23
struct bt_hci_evt_remote_ext_features_complete {
  u8 status;
  u16 handle;
  u8 page;
  u8 max_page;
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_EVT_SYNC_CONN_COMPLETE 0x2c
struct bt_hci_evt_sync_conn_complete {
  u8 status;
  u16 handle;
  u8 bdaddr[6];
  u8 link_type;
  u8 tx_interval;
  u8 retrans_window;
  u16 rx_pkt_len;
  u16 tx_pkt_len;
  u8 air_mode;
} __attribute__((packed));

#define BT_HCI_EVT_SYNC_CONN_CHANGED 0x2d
struct bt_hci_evt_sync_conn_changed {
  u8 status;
  u16 handle;
  u8 tx_interval;
  u8 retrans_window;
  u16 rx_pkt_len;
  u16 tx_pkt_len;
} __attribute__((packed));

#define BT_HCI_EVT_SNIFF_SUBRATING 0x2e
struct bt_hci_evt_sniff_subrating {
  u8 status;
  u16 handle;
  u16 max_tx_latency;
  u16 max_rx_latency;
  u16 min_remote_timeout;
  u16 min_local_timeout;
} __attribute__((packed));

#define BT_HCI_EVT_EXT_INQUIRY_RESULT 0x2f
struct bt_hci_evt_ext_inquiry_result {
  u8 num_resp;
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_period_mode;
  u8 dev_class[3];
  u16 clock_offset;
  int8_t rssi;
  u8 data[240];
} __attribute__((packed));

#define BT_HCI_EVT_ENCRYPT_KEY_REFRESH_COMPLETE 0x30
struct bt_hci_evt_encrypt_key_refresh_complete {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_IO_CAPABILITY_REQUEST 0x31
struct bt_hci_evt_io_capability_request {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_IO_CAPABILITY_RESPONSE 0x32
struct bt_hci_evt_io_capability_response {
  u8 bdaddr[6];
  u8 capability;
  u8 oob_data;
  u8 authentication;
} __attribute__((packed));

#define BT_HCI_EVT_USER_CONFIRM_REQUEST 0x33
struct bt_hci_evt_user_confirm_request {
  u8 bdaddr[6];
  u32 passkey;
} __attribute__((packed));

#define BT_HCI_EVT_USER_PASSKEY_REQUEST 0x34
struct bt_hci_evt_user_passkey_request {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_REMOTE_OOB_DATA_REQUEST 0x35
struct bt_hci_evt_remote_oob_data_request {
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_SIMPLE_PAIRING_COMPLETE 0x36
struct bt_hci_evt_simple_pairing_complete {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_LINK_SUPV_TIMEOUT_CHANGED 0x38
struct bt_hci_evt_link_supv_timeout_changed {
  u16 handle;
  u16 timeout;
} __attribute__((packed));

#define BT_HCI_EVT_ENHANCED_FLUSH_COMPLETE 0x39
struct bt_hci_evt_enhanced_flush_complete {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_USER_PASSKEY_NOTIFY 0x3b
struct bt_hci_evt_user_passkey_notify {
  u8 bdaddr[6];
  u32 passkey;
} __attribute__((packed));

#define BT_HCI_EVT_KEYPRESS_NOTIFY 0x3c
struct bt_hci_evt_keypress_notify {
  u8 bdaddr[6];
  u8 type;
} __attribute__((packed));

#define BT_HCI_EVT_REMOTE_HOST_FEATURES_NOTIFY 0x3d
struct bt_hci_evt_remote_host_features_notify {
  u8 bdaddr[6];
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_EVT_LE_META_EVENT 0x3e

#define BT_HCI_EVT_PHY_LINK_COMPLETE 0x40
struct bt_hci_evt_phy_link_complete {
  u8 status;
  u8 phy_handle;
} __attribute__((packed));

#define BT_HCI_EVT_CHANNEL_SELECTED 0x41
struct bt_hci_evt_channel_selected {
  u8 phy_handle;
} __attribute__((packed));

#define BT_HCI_EVT_DISCONN_PHY_LINK_COMPLETE 0x42
struct bt_hci_evt_disconn_phy_link_complete {
  u8 status;
  u8 phy_handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_EVT_PHY_LINK_LOSS_EARLY_WARNING 0x43
struct bt_hci_evt_phy_link_loss_early_warning {
  u8 phy_handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_EVT_PHY_LINK_RECOVERY 0x44
struct bt_hci_evt_phy_link_recovery {
  u8 phy_handle;
} __attribute__((packed));

#define BT_HCI_EVT_LOGIC_LINK_COMPLETE 0x45
struct bt_hci_evt_logic_link_complete {
  u8 status;
  u16 handle;
  u8 phy_handle;
  u8 flow_spec;
} __attribute__((packed));

#define BT_HCI_EVT_DISCONN_LOGIC_LINK_COMPLETE 0x46
struct bt_hci_evt_disconn_logic_link_complete {
  u8 status;
  u16 handle;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_EVT_FLOW_SPEC_MODIFY_COMPLETE 0x47
struct bt_hci_evt_flow_spec_modify_complete {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_NUM_COMPLETED_DATA_BLOCKS 0x48
struct bt_hci_evt_num_completed_data_blocks {
  u16 total_num_blocks;
  u8 num_handles;
  u16 handle;
  u16 num_packets;
  u16 num_blocks;
} __attribute__((packed));

#define BT_HCI_EVT_SHORT_RANGE_MODE_CHANGE 0x4c
struct bt_hci_evt_short_range_mode_change {
  u8 status;
  u8 phy_handle;
  u8 mode;
} __attribute__((packed));

#define BT_HCI_EVT_AMP_STATUS_CHANGE 0x4d
struct bt_hci_evt_amp_status_change {
  u8 status;
  u8 amp_status;
} __attribute__((packed));

#define BT_HCI_EVT_TRIGGERED_CLOCK_CAPTURE 0x4e
struct bt_hci_evt_triggered_clock_capture {
  u16 handle;
  u8 type;
  u32 clock;
  u16 clock_offset;
} __attribute__((packed));

#define BT_HCI_EVT_SYNC_TRAIN_COMPLETE 0x4f
struct bt_hci_evt_sync_train_complete {
  u8 status;
} __attribute__((packed));

#define BT_HCI_EVT_SYNC_TRAIN_RECEIVED 0x50
struct bt_hci_evt_sync_train_received {
  u8 status;
  u8 bdaddr[6];
  u32 offset;
  u8 map[10];
  u8 lt_addr;
  u32 instant;
  u16 interval;
  u8 service_data;
} __attribute__((packed));

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_RECEIVE 0x51
struct bt_hci_evt_peripheral_broadcast_receive {
  u8 bdaddr[6];
  u8 lt_addr;
  u32 clock;
  u32 offset;
  u8 status;
  u8 fragment;
  u8 length;
} __attribute__((packed));

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_TIMEOUT 0x52
struct bt_hci_evt_peripheral_broadcast_timeout {
  u8 bdaddr[6];
  u8 lt_addr;
} __attribute__((packed));

#define BT_HCI_EVT_TRUNCATED_PAGE_COMPLETE 0x53
struct bt_hci_evt_truncated_page_complete {
  u8 status;
  u8 bdaddr[6];
} __attribute__((packed));

#define BT_HCI_EVT_PERIPHERAL_PAGE_RESPONSE_TIMEOUT 0x54

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE 0x55
struct bt_hci_evt_channel_map_change {
  u8 map[10];
} __attribute__((packed));

#define BT_HCI_EVT_INQUIRY_RESPONSE_NOTIFY 0x56
struct bt_hci_evt_inquiry_response_notify {
  u8 lap[3];
  int8_t rssi;
} __attribute__((packed));

#define BT_HCI_EVT_AUTH_PAYLOAD_TIMEOUT_EXPIRED 0x57
struct bt_hci_evt_auth_payload_timeout_expired {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_LE_CONN_COMPLETE 0x01
struct bt_hci_evt_le_conn_complete {
  u8 status;
  u16 handle;
  u8 role;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u16 interval;
  u16 latency;
  u16 supv_timeout;
  u8 clock_accuracy;
} __attribute__((packed));

#define BT_HCI_EVT_LE_ADV_REPORT 0x02
struct bt_hci_evt_le_adv_report {
  u8 num_reports;
  u8 event_type;
  u8 addr_type;
  u8 addr[6];
  u8 data_len;
  u8 data[0];
} __attribute__((packed));

#define BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE 0x03
struct bt_hci_evt_le_conn_update_complete {
  u8 status;
  u16 handle;
  u16 interval;
  u16 latency;
  u16 supv_timeout;
} __attribute__((packed));

#define BT_HCI_EVT_LE_REMOTE_FEATURES_COMPLETE 0x04
struct bt_hci_evt_le_remote_features_complete {
  u8 status;
  u16 handle;
  u8 features[8];
} __attribute__((packed));

#define BT_HCI_EVT_LE_LONG_TERM_KEY_REQUEST 0x05
struct bt_hci_evt_le_long_term_key_request {
  u16 handle;
  u64 rand;
  u16 ediv;
} __attribute__((packed));

#define BT_HCI_EVT_LE_CONN_PARAM_REQUEST 0x06
struct bt_hci_evt_le_conn_param_request {
  u16 handle;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
} __attribute__((packed));

#define BT_HCI_EVT_LE_DATA_LENGTH_CHANGE 0x07
struct bt_hci_evt_le_data_length_change {
  u16 handle;
  u16 max_tx_len;
  u16 max_tx_time;
  u16 max_rx_len;
  u16 max_rx_time;
} __attribute__((packed));

#define BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE 0x08
struct bt_hci_evt_le_read_local_pk256_complete {
  u8 status;
  u8 local_pk256[64];
} __attribute__((packed));

#define BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE 0x09
struct bt_hci_evt_le_generate_dhkey_complete {
  u8 status;
  u8 dhkey[32];
} __attribute__((packed));

#define BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE 0x0a
struct bt_hci_evt_le_enhanced_conn_complete {
  u8 status;
  u16 handle;
  u8 role;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u8 local_rpa[6];
  u8 peer_rpa[6];
  u16 interval;
  u16 latency;
  u16 supv_timeout;
  u8 clock_accuracy;
} __attribute__((packed));

#define BT_HCI_EVT_LE_DIRECT_ADV_REPORT 0x0b
struct bt_hci_evt_le_direct_adv_report {
  u8 num_reports;
  u8 event_type;
  u8 addr_type;
  u8 addr[6];
  u8 direct_addr_type;
  u8 direct_addr[6];
  int8_t rssi;
} __attribute__((packed));

#define BT_HCI_EVT_LE_PHY_UPDATE_COMPLETE 0x0c
struct bt_hci_evt_le_phy_update_complete {
  u8 status;
  u16 handle;
  u8 tx_phy;
  u8 rx_phy;
} __attribute__((packed));

#define BT_HCI_EVT_LE_EXT_ADV_REPORT 0x0d
struct bt_hci_evt_le_ext_adv_report {
  u8 num_reports;
} __attribute__((packed));
struct bt_hci_le_ext_adv_report {
  u16 event_type;
  u8 addr_type;
  u8 addr[6];
  u8 primary_phy;
  u8 secondary_phy;
  u8 sid;
  u8 tx_power;
  int8_t rssi;
  u16 interval;
  u8 direct_addr_type;
  u8 direct_addr[6];
  u8 data_len;
  u8 data[0];
} __attribute__((packed));

#define BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED 0x0e
struct bt_hci_evt_le_per_sync_established {
  u8 status;
  u16 handle;
  u8 sid;
  u8 addr_type;
  u8 addr[6];
  u8 phy;
  u16 interval;
  u8 clock_accuracy;
} __attribute__((packed));

#define BT_HCI_EVT_LE_PA_REPORT 0x0f
struct bt_hci_le_pa_report {
  u16 handle;
  u8 tx_power;
  int8_t rssi;
  u8 cte_type;
  u8 data_status;
  u8 data_len;
  u8 data[0];
} __attribute__((packed));

#define BT_HCI_EVT_LE_PA_SYNC_LOST 0x10
struct bt_hci_evt_le_per_sync_lost {
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_LE_ADV_SET_TERM 0x12
struct bt_hci_evt_le_adv_set_term {
  u8 status;
  u8 handle;
  u16 conn_handle;
  u8 num_evts;
} __attribute__((packed));

#define BT_HCI_EVT_LE_SCAN_REQ_RECEIVED 0x13
struct bt_hci_evt_le_scan_req_received {
  u8 handle;
  u8 scanner_addr_type;
  u8 scanner_addr[6];
} __attribute__((packed));

#define BT_HCI_EVT_LE_CHAN_SELECT_ALG 0x14
struct bt_hci_evt_le_chan_select_alg {
  u16 handle;
  u8 algorithm;
} __attribute__((packed));

#define BT_HCI_EVT_LE_CTE_REQUEST_FAILED 0x17
struct bt_hci_evt_le_cte_request_failed {
  u8 status;
  u16 handle;
} __attribute__((packed));

#define BT_HCI_EVT_LE_PA_SYNC_TRANS_REC 0x18
struct bt_hci_evt_le_pa_sync_trans_rec {
  u8 status;
  u16 handle;
  u16 service_data;
  u16 sync_handle;
  u8 sid;
  u8 addr_type;
  u8 addr[6];
  u8 phy;
  u16 interval;
  u8 clock_accuracy;
} __attribute__((packed));

#define BT_HCI_EVT_LE_CIS_ESTABLISHED 0x19
struct bt_hci_evt_le_cis_established {
  u8 status;
  u16 conn_handle;
  u8 cig_sync_delay[3];
  u8 cis_sync_delay[3];
  u8 c_latency[3];
  u8 p_latency[3];
  u8 c_phy;
  u8 p_phy;
  u8 nse;
  u8 c_bn;
  u8 p_bn;
  u8 c_ft;
  u8 p_ft;
  u16 c_mtu;
  u16 p_mtu;
  u16 interval;
} __attribute__((packed));

#define BT_HCI_EVT_LE_CIS_REQ 0x1a
struct bt_hci_evt_le_cis_req {
  u16 acl_handle;
  u16 cis_handle;
  u8 cig_id;
  u8 cis_id;
} __attribute__((packed));

#define BT_HCI_EVT_LE_BIG_COMPLETE 0x1b
struct bt_hci_evt_le_big_complete {
  u8 status;
  u8 handle;
  u8 sync_delay[3];
  u8 latency[3];
  u8 phy;
  u8 nse;
  u8 bn;
  u8 pto;
  u8 irc;
  u16 max_pdu;
  u16 interval;
  u8 num_bis;
  u16 bis_handle[0];
} __attribute__((packed));

#define BT_HCI_EVT_LE_BIG_TERMINATE 0x1c
struct bt_hci_evt_le_big_terminate {
  u8 reason;
  u8 handle;
} __attribute__((packed));

#define BT_HCI_EVT_LE_BIG_SYNC_ESTABILISHED 0x1d
struct bt_hci_evt_le_big_sync_estabilished {
  u8 status;
  u8 handle;
  u8 latency[3];
  u8 nse;
  u8 bn;
  u8 pto;
  u8 irc;
  u16 max_pdu;
  u16 interval;
  u8 num_bis;
  u16 bis[0];
} __attribute__((packed));

#define BT_HCI_EVT_LE_BIG_SYNC_LOST 0x1e
struct bt_hci_evt_le_big_sync_lost {
  u8 big_id;
  u8 reason;
} __attribute__((packed));

#define BT_HCI_EVT_LE_REQ_PEER_SCA_COMPLETE 0x1f
struct bt_hci_evt_le_req_peer_sca_complete {
  u8 status;
  u16 handle;
  u8 sca;
} __attribute__((packed));

#define BT_HCI_ERR_SUCCESS 0x00
#define BT_HCI_ERR_UNKNOWN_COMMAND 0x01
#define BT_HCI_ERR_UNKNOWN_CONN_ID 0x02
#define BT_HCI_ERR_HARDWARE_FAILURE 0x03
#define BT_HCI_ERR_PAGE_TIMEOUT 0x04
#define BT_HCI_ERR_AUTH_FAILURE 0x05
#define BT_HCI_ERR_PIN_OR_KEY_MISSING 0x06
#define BT_HCI_ERR_MEM_CAPACITY_EXCEEDED 0x07
#define BT_HCI_ERR_COMMAND_DISALLOWED 0x0c
#define BT_HCI_ERR_UNSUPPORTED_FEATURE 0x11
#define BT_HCI_ERR_INVALID_PARAMETERS 0x12
#define BT_HCI_ERR_UNSPECIFIED_ERROR 0x1f
#define BT_HCI_ERR_ADV_TIMEOUT 0x3c
#define BT_HCI_ERR_CONN_FAILED_TO_ESTABLISH 0x3e
#define BT_HCI_ERR_UNKNOWN_ADVERTISING_ID 0x42
#define BT_HCI_ERR_CANCELLED 0x44

struct bt_l2cap_hdr {
  u16 len;
  u16 cid;
  u8 data[];
} __attribute__((packed));

struct bt_l2cap_hdr_sig {
  u8 code;
  u8 ident;
  u16 len;
} __attribute__((packed));

#define BT_L2CAP_PDU_CMD_REJECT 0x01
struct bt_l2cap_pdu_cmd_reject {
  u16 reason;
} __attribute__((packed));

#define BT_L2CAP_PDU_CONN_REQ 0x02
struct bt_l2cap_pdu_conn_req {
  u16 psm;
  u16 scid;
} __attribute__((packed));

#define BT_L2CAP_PDU_CONN_RSP 0x03
struct bt_l2cap_pdu_conn_rsp {
  u16 dcid;
  u16 scid;
  u16 result;
  u16 status;
} __attribute__((packed));

#define BT_L2CAP_PDU_CONFIG_REQ 0x04
struct bt_l2cap_pdu_config_req {
  u16 dcid;
  u16 flags;
} __attribute__((packed));

#define BT_L2CAP_PDU_CONFIG_RSP 0x05
struct bt_l2cap_pdu_config_rsp {
  u16 scid;
  u16 flags;
  u16 result;
} __attribute__((packed));

#define BT_L2CAP_PDU_DISCONN_REQ 0x06
struct bt_l2cap_pdu_disconn_req {
  u16 dcid;
  u16 scid;
} __attribute__((packed));

#define BT_L2CAP_PDU_DISCONN_RSP 0x07
struct bt_l2cap_pdu_disconn_rsp {
  u16 dcid;
  u16 scid;
} __attribute__((packed));

#define BT_L2CAP_PDU_ECHO_REQ 0x08

#define BT_L2CAP_PDU_ECHO_RSP 0x09

#define BT_L2CAP_PDU_INFO_REQ 0x0a
struct bt_l2cap_pdu_info_req {
  u16 type;
} __attribute__((packed));

#define BT_L2CAP_PDU_INFO_RSP 0x0b
struct bt_l2cap_pdu_info_rsp {
  u16 type;
  u16 result;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_PDU_CREATE_CHAN_REQ 0x0c
struct bt_l2cap_pdu_create_chan_req {
  u16 psm;
  u16 scid;
  u8 ctrlid;
} __attribute__((packed));

#define BT_L2CAP_PDU_CREATE_CHAN_RSP 0x0d
struct bt_l2cap_pdu_create_chan_rsp {
  u16 dcid;
  u16 scid;
  u16 result;
  u16 status;
} __attribute__((packed));

#define BT_L2CAP_PDU_MOVE_CHAN_REQ 0x0e
struct bt_l2cap_pdu_move_chan_req {
  u16 icid;
  u8 ctrlid;
} __attribute__((packed));

#define BT_L2CAP_PDU_MOVE_CHAN_RSP 0x0f
struct bt_l2cap_pdu_move_chan_rsp {
  u16 icid;
  u16 result;
} __attribute__((packed));

#define BT_L2CAP_PDU_MOVE_CHAN_CFM 0x10
struct bt_l2cap_pdu_move_chan_cfm {
  u16 icid;
  u16 result;
} __attribute__((packed));

#define BT_L2CAP_PDU_MOVE_CHAN_CFM_RSP 0x11
struct bt_l2cap_pdu_move_chan_cfm_rsp {
  u16 icid;
} __attribute__((packed));

#define BT_L2CAP_PDU_CONN_PARAM_REQ 0x12
struct bt_l2cap_pdu_conn_param_req {
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 timeout;
} __attribute__((packed));

#define BT_L2CAP_PDU_CONN_PARAM_RSP 0x13
struct bt_l2cap_pdu_conn_param_rsp {
  u16 result;
} __attribute__((packed));

#define BT_L2CAP_PDU_LE_CONN_REQ 0x14
struct bt_l2cap_pdu_le_conn_req {
  u16 psm;
  u16 scid;
  u16 mtu;
  u16 mps;
  u16 credits;
} __attribute__((packed));

#define BT_L2CAP_PDU_LE_CONN_RSP 0x15
struct bt_l2cap_pdu_le_conn_rsp {
  u16 dcid;
  u16 mtu;
  u16 mps;
  u16 credits;
  u16 result;
} __attribute__((packed));

#define BT_L2CAP_PDU_LE_FLOWCTL_CREDS 0x16
struct bt_l2cap_pdu_le_flowctl_creds {
  u16 cid;
  u16 credits;
} __attribute__((packed));

#define BT_L2CAP_PDU_ECRED_CONN_REQ 0x17
struct bt_l2cap_pdu_ecred_conn_req {
  u16 psm;
  u16 mtu;
  u16 mps;
  u16 credits;
  u16 scid[0];
} __attribute__((packed));

#define BT_L2CAP_PDU_ECRED_CONN_RSP 0x18
struct bt_l2cap_pdu_ecred_conn_rsp {
  u16 mtu;
  u16 mps;
  u16 credits;
  u16 result;
  u16 dcid[0];
} __attribute__((packed));

#define BT_L2CAP_PDU_ECRED_RECONF_REQ 0x19
struct bt_l2cap_pdu_ecred_reconf_req {
  u16 mtu;
  u16 mps;
  u16 scid[0];
} __attribute__((packed));

#define BT_L2CAP_PDU_ECRED_RECONF_RSP 0x1a
struct bt_l2cap_pdu_ecred_reconf_rsp {
  u16 result;
} __attribute__((packed));

struct bt_l2cap_hdr_connless {
  u16 psm;
} __attribute__((packed));

struct bt_l2cap_hdr_amp {
  u8 code;
  u8 ident;
  u16 len;
} __attribute__((packed));

#define BT_L2CAP_AMP_CMD_REJECT 0x01
struct bt_l2cap_amp_cmd_reject {
  u16 reason;
} __attribute__((packed));

#define BT_L2CAP_AMP_DISCOVER_REQ 0x02
struct bt_l2cap_amp_discover_req {
  u16 size;
  u16 features;
} __attribute__((packed));

#define BT_L2CAP_AMP_DISCOVER_RSP 0x03
struct bt_l2cap_amp_discover_rsp {
  u16 size;
  u16 features;
} __attribute__((packed));

#define BT_L2CAP_AMP_CHANGE_NOTIFY 0x04

#define BT_L2CAP_AMP_CHANGE_RESPONSE 0x05

#define BT_L2CAP_AMP_GET_INFO_REQ 0x06
struct bt_l2cap_amp_get_info_req {
  u8 ctrlid;
} __attribute__((packed));

#define BT_L2CAP_AMP_GET_INFO_RSP 0x07
struct bt_l2cap_amp_get_info_rsp {
  u8 ctrlid;
  u8 status;
  u32 total_bw;
  u32 max_bw;
  u32 min_latency;
  u16 pal_cap;
  u16 max_assoc_len;
} __attribute__((packed));

#define BT_L2CAP_AMP_GET_ASSOC_REQ 0x08
struct bt_l2cap_amp_get_assoc_req {
  u8 ctrlid;
} __attribute__((packed));

#define BT_L2CAP_AMP_GET_ASSOC_RSP 0x09
struct bt_l2cap_amp_get_assoc_rsp {
  u8 ctrlid;
  u8 status;
} __attribute__((packed));

#define BT_L2CAP_AMP_CREATE_PHY_LINK_REQ 0x0a
struct bt_l2cap_amp_create_phy_link_req {
  u8 local_ctrlid;
  u8 remote_ctrlid;
} __attribute__((packed));

#define BT_L2CAP_AMP_CREATE_PHY_LINK_RSP 0x0b
struct bt_l2cap_amp_create_phy_link_rsp {
  u8 local_ctrlid;
  u8 remote_ctrlid;
  u8 status;
} __attribute__((packed));

#define BT_L2CAP_AMP_DISCONN_PHY_LINK_REQ 0x0c
struct bt_l2cap_amp_disconn_phy_link_req {
  u8 local_ctrlid;
  u8 remote_ctrlid;
} __attribute__((packed));

#define BT_L2CAP_AMP_DISCONN_PHY_LINK_RSP 0x0d
struct bt_l2cap_amp_disconn_phy_link_rsp {
  u8 local_ctrlid;
  u8 remote_ctrlid;
  u8 status;
} __attribute__((packed));

struct bt_l2cap_hdr_att {
  u8 code;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_ERROR_RESPONSE 0x01
struct bt_l2cap_att_error_response {
  u8 request;
  u16 handle;
  u8 error;
} __attribute__((packed));

#define BT_L2CAP_ATT_EXCHANGE_MTU_REQ 0x02
struct bt_l2cap_att_exchange_mtu_req {
  u16 mtu;
} __attribute__((packed));

#define BT_L2CAP_ATT_EXCHANGE_MTU_RSP 0x03
struct bt_l2cap_att_exchange_mtu_rsp {
  u16 mtu;
} __attribute__((packed));

#define BT_L2CAP_ATT_FIND_INFORMATION_REQ 0x04
struct bt_l2cap_att_find_information_req {
  u16 start_handle;
  u16 end_handle;
} __attribute__((packed));

#define BT_L2CAP_ATT_FIND_INFORMATION_RSP 0x05
struct bt_l2cap_att_find_information_rsp {
  u8 format;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_FIND_TYPE_VALUE_REQ 0x06
struct bt_l2cap_att_find_type_value_req {
  u16 start_handle;
  u16 end_handle;
  u16 type;
  u8 value[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_FIND_TYPE_VALUE_RSP 0x07
struct bt_l2cap_att_find_type_value_rsp {
  u8 list[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_TYPE_REQ 0x08
struct bt_l2cap_att_read_type_req {
  u16 start_handle;
  u16 end_handle;
  u8 type[16];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_TYPE_RSP 0x09
struct bt_l2cap_att_read_type_rsp {
  u8 length;
  u8 list[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_REQ 0x0a
struct bt_l2cap_att_read_req {
  u16 handle;
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_RSP 0x0b
struct bt_l2cap_att_read_rsp {
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_BLOB_REQ 0x0c
struct bt_l2cap_att_read_blob_req {
  u16 handle;
  u16 offset;
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_BLOB_RSP 0x0d
struct bt_l2cap_att_read_blob_rsp {
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_MULTIPLE_REQ 0x0e
struct bt_l2cap_att_read_multiple_req {
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_MULTIPLE_RSP 0x0f
struct bt_l2cap_att_read_multiple_rsp {
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_GROUP_TYPE_REQ 0x10
struct bt_l2cap_att_read_group_type_req {
  u16 start_handle;
  u16 end_handle;
  u8 type[16];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_GROUP_TYPE_RSP 0x11
struct bt_l2cap_att_read_group_type_rsp {
  u8 length;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_MULTIPLE_VARIABLE_REQ 0x20
struct bt_l2cap_att_read_multiple_variable_req {
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_READ_MULTIPLE_VARIABLE_RSP 0x21
struct bt_l2cap_att_read_multiple_variable_rsp {
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_WRITE_REQ 0x12
struct bt_l2cap_att_write_req {
  u16 handle;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_WRITE_RSP 0x13
struct bt_l2cap_att_write_rsp {
} __attribute__((packed));

#define BT_L2CAP_ATT_WRITE_CMD 0x52
struct bt_l2cap_att_write_cmd {
  u16 handle;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_SIGNED_WRITE_CMD 0xd2
struct bt_l2cap_att_signed_write_cmd {
  u16 handle;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_PREPARE_WRITE_REQ 0x16
struct bt_l2cap_att_prepare_write_req {
  u16 handle;
  u16 offset;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_PREPARE_WRITE_RSP 0x17
struct bt_l2cap_att_prepare_write_rsp {
  u16 handle;
  u16 offset;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_EXECUTE_WRITE_REQ 0x18
struct bt_l2cap_att_execute_write_req {
  u8 flags;
} __attribute__((packed));

#define BT_L2CAP_ATT_EXECUTE_WRITE_RSP 0x19
struct bt_l2cap_att_execute_write_rsp {
} __attribute__((packed));

#define BT_L2CAP_ATT_HANDLE_VALUE_NOTIFY 0x1b
struct bt_l2cap_att_handle_value_notify {
  u16 handle;
  u8 data[0];
} __attribute__((packed));

#define BT_L2CAP_ATT_HANDLE_VALUE_IND 0x1d
struct bt_l2cap_att_handle_value_ind {
  u16 handle;
} __attribute__((packed));

#define BT_L2CAP_ATT_HANDLE_VALUE_CONF 0x1e
struct bt_l2cap_att_handle_value_conf{
} __attribute__((packed));

#define BT_L2CAP_ATT_MULTIPLE_HANDLE_VALUE_NTF 0x23
struct bt_l2cap_att_multiple_handle_value_ntf {
  u8 data[0];
} __attribute__((packed));

struct bt_l2cap_hdr_smp {
  u8 code;
} __attribute__((packed));

#define BT_L2CAP_SMP_PAIRING_REQUEST 0x01
struct bt_l2cap_smp_pairing_request {
  u8 io_capa;
  u8 oob_data;
  u8 auth_req;
  u8 max_key_size;
  u8 init_key_dist;
  u8 resp_key_dist;
} __attribute__((packed));

#define BT_L2CAP_SMP_PAIRING_RESPONSE 0x02
struct bt_l2cap_smp_pairing_response {
  u8 io_capa;
  u8 oob_data;
  u8 auth_req;
  u8 max_key_size;
  u8 init_key_dist;
  u8 resp_key_dist;
} __attribute__((packed));

#define BT_L2CAP_SMP_PAIRING_CONFIRM 0x03
struct bt_l2cap_smp_pairing_confirm {
  u8 value[16];
} __attribute__((packed));

#define BT_L2CAP_SMP_PAIRING_RANDOM 0x04
struct bt_l2cap_smp_pairing_random {
  u8 value[16];
} __attribute__((packed));

#define BT_L2CAP_SMP_PAIRING_FAILED 0x05
struct bt_l2cap_smp_pairing_failed {
  u8 reason;
} __attribute__((packed));

#define BT_L2CAP_SMP_ENCRYPT_INFO 0x06
struct bt_l2cap_smp_encrypt_info {
  u8 ltk[16];
} __attribute__((packed));

#define BT_L2CAP_SMP_CENTRAL_IDENT 0x07
struct bt_l2cap_smp_central_ident {
  u16 ediv;
  u64 rand;
} __attribute__((packed));

#define BT_L2CAP_SMP_IDENT_INFO 0x08
struct bt_l2cap_smp_ident_info {
  u8 irk[16];
} __attribute__((packed));

#define BT_L2CAP_SMP_IDENT_ADDR_INFO 0x09
struct bt_l2cap_smp_ident_addr_info {
  u8 addr_type;
  u8 addr[6];
} __attribute__((packed));

#define BT_L2CAP_SMP_SIGNING_INFO 0x0a
struct bt_l2cap_smp_signing_info {
  u8 csrk[16];
} __attribute__((packed));

#define BT_L2CAP_SMP_SECURITY_REQUEST 0x0b
struct bt_l2cap_smp_security_request {
  u8 auth_req;
} __attribute__((packed));

#define BT_L2CAP_SMP_PUBLIC_KEY 0x0c
struct bt_l2cap_smp_public_key {
  u8 x[32];
  u8 y[32];
} __attribute__((packed));

#define BT_L2CAP_SMP_DHKEY_CHECK 0x0d
struct bt_l2cap_smp_dhkey_check {
  u8 e[16];
} __attribute__((packed));

#define BT_L2CAP_SMP_KEYPRESS_NOTIFY 0x0e
struct bt_l2cap_smp_keypress_notify {
  u8 type;
} __attribute__((packed));

struct bt_sdp_hdr {
  u8 pdu;
  u16 tid;
  u16 plen;
} __attribute__((packed));

// MARK: Attribute PDU Opcodes
#define ATT_ERROR_RESPONSE 0x01u

#define ATT_EXCHANGE_MTU_REQUEST 0x02u
#define ATT_EXCHANGE_MTU_RESPONSE 0x03u

#define ATT_FIND_INFORMATION_REQUEST 0x04u
#define ATT_FIND_INFORMATION_REPLY 0x05u
#define ATT_FIND_BY_TYPE_VALUE_REQUEST 0x06u
#define ATT_FIND_BY_TYPE_VALUE_RESPONSE 0x07u

#define ATT_READ_BY_TYPE_REQUEST 0x08u
#define ATT_READ_BY_TYPE_RESPONSE 0x09u
#define ATT_READ_REQUEST 0x0au
#define ATT_READ_RESPONSE 0x0bu
#define ATT_READ_BLOB_REQUEST 0x0cu
#define ATT_READ_BLOB_RESPONSE 0x0du
#define ATT_READ_MULTIPLE_REQUEST 0x0eu
#define ATT_READ_MULTIPLE_RESPONSE 0x0fu
#define ATT_READ_BY_GROUP_TYPE_REQUEST 0x10u
#define ATT_READ_BY_GROUP_TYPE_RESPONSE 0x11u

#define ATT_WRITE_REQUEST 0x12u
#define ATT_WRITE_RESPONSE 0x13u

#define ATT_PREPARE_WRITE_REQUEST 0x16u
#define ATT_PREPARE_WRITE_RESPONSE 0x17u
#define ATT_EXECUTE_WRITE_REQUEST 0x18u
#define ATT_EXECUTE_WRITE_RESPONSE 0x19u

#define ATT_HANDLE_VALUE_NOTIFICATION 0x1bu
#define ATT_HANDLE_VALUE_INDICATION 0x1du
#define ATT_HANDLE_VALUE_CONFIRMATION 0x1eu

#define ATT_READ_MULTIPLE_VARIABLE_REQ 0x20u
#define ATT_READ_MULTIPLE_VARIABLE_RSP 0x21u
#define ATT_MULTIPLE_HANDLE_VALUE_NTF 0x23u

#define ATT_WRITE_COMMAND 0x52u
#define ATT_SIGNED_WRITE_COMMAND 0xD2u

// internal additions
// 128 bit UUID used
#define ATT_PROPERTY_UUID128 0x200u
// Read/Write Permission bits
#define ATT_PROPERTY_READ_PERMISSION_BIT_0 0x0400u
#define ATT_PROPERTY_READ_PERMISSION_BIT_1 0x0800u
#define ATT_PROPERTY_WRITE_PERMISSION_BIT_0 0x0001u
#define ATT_PROPERTY_WRITE_PERMISSION_BIT_1 0x0010u
#define ATT_PROPERTY_READ_PERMISSION_SC 0x0020u
#define ATT_PROPERTY_WRITE_PERMISSION_SC 0x0080u


#endif /* D9164AF1_4E22_4376_82E6_9C574FB08463 */
