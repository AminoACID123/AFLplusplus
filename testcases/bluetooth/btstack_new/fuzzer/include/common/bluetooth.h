#ifndef D9164AF1_4E22_4376_82E6_9C574FB08463
#define D9164AF1_4E22_4376_82E6_9C574FB08463

#include "type.h"

#define HCI_OPCODE(OGF, OCF) ((OCF) | ((OGF) << 10))

#define HCI_COMMAND_DATA_PACKET 0x01
#define HCI_ACL_DATA_PACKET 0x02
#define HCI_SCO_DATA_PACKET 0x03
#define HCI_EVENT_PACKET 0x04
#define HCI_ISO_DATA_PACKET 0x05

#define BD_ADDR_LEN 6
typedef uint8_t bd_addr_t[BD_ADDR_LEN];
typedef enum {
  BD_ADDR_TYPE_LE_PUBLIC = 0,
  BD_ADDR_TYPE_LE_RANDOM = 1,
  BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_PUBLIC = 2,
  BD_ADDR_TYPE_LE_PRIVAT_FALLBACK_RANDOM = 3,
  BD_ADDR_TYPE_SCO = 0xfc,
  BD_ADDR_TYPE_ACL = 0xfd,
  BD_ADDR_TYPE_UNKNOWN = 0xfe, // also used as 'invalid'
} bd_addr_type_t;

typedef uint8_t sm_key_t[16];



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





#define BT_HCI_CMD_BIT(_byte, _bit) ((8 * _byte) + _bit)

typedef struct __attribute__((packed)) {
  u8 preamble;
  u32 access_addr;
} bt_ll_hdr;

#define BT_LL_CONN_UPDATE_REQ 0x00
typedef struct __attribute__((packed)) {
  u8 win_size;
  u16 win_offset;
  u16 interval;
  u16 latency;
  u16 timeout;
  u16 instant;
} bt_ll_conn_update_req;

#define BT_LL_CHANNEL_MAP_REQ 0x01
typedef struct __attribute__((packed)) {
  u8 map[5];
  u16 instant;
} bt_ll_channel_map_req;

#define BT_LL_TERMINATE_IND 0x02
typedef struct __attribute__((packed)) {
  u8 error;
} bt_ll_terminate_ind;

#define BT_LL_ENC_REQ 0x03
typedef struct __attribute__((packed)) {
  u64 rand;
  u16 ediv;
  u64 skd;
  u32 iv;
} bt_ll_enc_req;

#define BT_LL_ENC_RSP 0x04
typedef struct __attribute__((packed)) {
  u64 skd;
  u32 iv;
} bt_ll_enc_rsp;

#define BT_LL_START_ENC_REQ 0x05

#define BT_LL_START_ENC_RSP 0x06

#define BT_LL_UNKNOWN_RSP 0x07
typedef struct __attribute__((packed)) {
  u8 type;
} bt_ll_unknown_rsp;

#define BT_LL_FEATURE_REQ 0x08
typedef struct __attribute__((packed)) {
  u8 features[8];
} bt_ll_feature_req;

#define BT_LL_FEATURE_RSP 0x09
typedef struct __attribute__((packed)) {
  u8 features[8];
} bt_ll_feature_rsp;

#define BT_LL_PAUSE_ENC_REQ 0x0a

#define BT_LL_PAUSE_ENC_RSP 0x0b

#define BT_LL_VERSION_IND 0x0c
typedef struct __attribute__((packed)) {
  u8 version;
  u16 company;
  u16 subversion;
} bt_ll_version_ind;

#define BT_LL_REJECT_IND 0x0d
typedef struct __attribute__((packed)) {
  u8 error;
} bt_ll_reject_ind;

#define BT_LL_PERIPHERAL_FEATURE_REQ 0x0e
typedef struct __attribute__((packed)) {
  u8 features[8];
} bt_ll_peripheral_feature_req;

#define BT_LL_CONN_PARAM_REQ 0x0f

#define BT_LL_CONN_PARAM_RSP 0x10

#define BT_LL_REJECT_IND_EXT 0x11
typedef struct __attribute__((packed)) {
  u8 opcode;
  u8 error;
} bt_ll_reject_ind_ext;

#define BT_LL_PING_REQ 0x12

#define BT_LL_PING_RSP 0x13

#define BT_LL_LENGTH_REQ 0x14
typedef struct __attribute__((packed)) {
  u16 rx_len;
  u16 rx_time;
  u16 tx_len;
  u16 tx_time;
} bt_ll_length;

#define BT_LL_LENGTH_RSP 0x15

#define BT_LL_PHY_REQ 0x16
typedef struct __attribute__((packed)) {
  u8 tx_phys;
  u8 rx_phys;
} bt_ll_phy;

#define BT_LL_PHY_RSP 0x17

#define BT_LL_PHY_UPDATE_IND 0x18
typedef struct __attribute__((packed)) {
  u8 c_phy;
  u8 p_phy;
  u16 instant;
} bt_ll_phy_update_ind;

#define BT_LL_MIN_USED_CHANNELS 0x19
typedef struct __attribute__((packed)) {
  u8 phys;
  u8 min_channels;
} bt_ll_min_used_channels;

#define BT_LL_CTE_REQ 0x1a
typedef struct __attribute__((packed)) {
  u8 cte;
} bt_ll_cte_req;

#define BT_LL_CTE_RSP 0x1b

#define BT_LL_PERIODIC_SYNC_IND 0x1c
typedef struct __attribute__((packed)) {
  u16 id;
  u8 info[18];
  u16 event_count;
  u16 last_counter;
  u8 adv_info;
  u8 phy;
  u8 adv_addr[6];
  u16 sync_counter;
} bt_ll_periodic_sync_ind;

#define BT_LL_CLOCK_ACCURACY_REQ 0x1d
typedef struct __attribute__((packed)) {
  u8 sca;
} bt_ll_clock_acc;

#define BT_LL_CLOCK_ACCURACY_RSP 0x1e

#define BT_LL_CIS_REQ 0x1f
typedef struct __attribute__((packed)) {
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
} bt_ll_cis_req;

#define BT_LL_CIS_RSP 0x20
typedef struct __attribute__((packed)) {
  u8 offset_min[3];
  u8 offset_max[3];
  u16 conn_event_count;
} bt_ll_cis_rsp;

#define BT_LL_CIS_IND 0x21
typedef struct __attribute__((packed)) {
  u32 addr;
  u8 cis_offset[3];
  u8 cig_sync_delay[3];
  u8 cis_sync_delay[3];
  u16 conn_event_count;
} bt_ll_cis_ind;

#define BT_LL_CIS_TERMINATE_IND 0x22
typedef struct __attribute__((packed)) {
  u8 cig;
  u8 cis;
  u8 reason;
} bt_ll_cis_term_ind;

#define LMP_ESC4(x) ((127 << 8) | (x))

#define BT_LMP_NAME_REQ 1
typedef struct __attribute__((packed)) {
  u8 offset;
} bt_lmp_name_req;

#define BT_LMP_NAME_RSP 2
typedef struct __attribute__((packed)) {
  u8 offset;
  u8 length;
  u8 fragment[14];
} bt_lmp_name_rsp;

#define BT_LMP_ACCEPTED 3
typedef struct __attribute__((packed)) {
  u8 opcode;
} bt_lmp_accepted;

#define BT_LMP_NOT_ACCEPTED 4
typedef struct __attribute__((packed)) {
  u8 opcode;
  u8 error;
} bt_lmp_not_accepted;

#define BT_LMP_CLKOFFSET_REQ 5

#define BT_LMP_CLKOFFSET_RSP 6
typedef struct __attribute__((packed)) {
  u16 offset;
} bt_lmp_clkoffset_rsp;

#define BT_LMP_DETACH 7
typedef struct __attribute__((packed)) {
  u8 error;
} bt_lmp_detach;

#define BT_LMP_AU_RAND 11
typedef struct __attribute__((packed)) {
  u8 number[16];
} bt_lmp_au_rand;

#define BT_LMP_SRES 12
typedef struct __attribute__((packed)) {
  u8 response[4];
} bt_lmp_sres;

#define BT_LMP_ENCRYPTION_MODE_REQ 15
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_lmp_encryption_mode_req;

#define BT_LMP_ENCRYPTION_KEY_SIZE_REQ 16
typedef struct __attribute__((packed)) {
  u8 key_size;
} bt_lmp_encryption_key_size_req;

#define BT_LMP_START_ENCRYPTION_REQ 17
typedef struct __attribute__((packed)) {
  u8 number[16];
} bt_lmp_start_encryption_req;

#define BT_LMP_STOP_ENCRYPTION_REQ 18

#define BT_LMP_SWITCH_REQ 19
typedef struct __attribute__((packed)) {
  u32 instant;
} bt_lmp_switch_req;

#define BT_LMP_UNSNIFF_REQ 24

#define BT_LMP_MAX_POWER 33

#define BT_LMP_MIN_POWER 34

#define BT_LMP_AUTO_RATE 35

#define BT_LMP_PREFERRED_RATE 36
typedef struct __attribute__((packed)) {
  u8 rate;
} bt_lmp_preferred_rate;

#define BT_LMP_VERSION_REQ 37
typedef struct __attribute__((packed)) {
  u8 version;
  u16 company;
  u16 subversion;
} bt_lmp_version_req;

#define BT_LMP_VERSION_RES 38
typedef struct __attribute__((packed)) {
  u8 version;
  u16 company;
  u16 subversion;
} bt_lmp_version_res;

#define BT_LMP_FEATURES_REQ 39
typedef struct __attribute__((packed)) {
  u8 features[8];
} bt_lmp_features_req;

#define BT_LMP_FEATURES_RES 40
typedef struct __attribute__((packed)) {
  u8 features[8];
} bt_lmp_features_res;

#define BT_LMP_MAX_SLOT 45
typedef struct __attribute__((packed)) {
  u8 slots;
} bt_lmp_max_slot;

#define BT_LMP_MAX_SLOT_REQ 46
typedef struct __attribute__((packed)) {
  u8 slots;
} bt_lmp_max_slot_req;

#define BT_LMP_TIMING_ACCURACY_REQ 47

#define BT_LMP_TIMING_ACCURACY_RES 48
typedef struct __attribute__((packed)) {
  u8 drift;
  u8 jitter;
} bt_lmp_timing_accuracy_res;

#define BT_LMP_SETUP_COMPLETE 49

#define BT_LMP_USE_SEMI_PERMANENT_KEY 50

#define BT_LMP_HOST_CONNECTION_REQ 51

#define BT_LMP_SLOT_OFFSET 52
typedef struct __attribute__((packed)) {
  u16 offset;
  u8 bdaddr[6];
} bt_lmp_slot_offset;

#define BT_LMP_PAGE_SCAN_MODE_REQ 54
typedef struct __attribute__((packed)) {
  u8 scheme;
  u8 settings;
} bt_lmp_page_scan_mode_req;

#define BT_LMP_TEST_ACTIVATE 56

#define BT_LMP_ENCRYPTION_KEY_SIZE_MASK_REQ 58

#define BT_LMP_SET_AFH 60
typedef struct __attribute__((packed)) {
  u32 instant;
  u8 mode;
  u8 map[10];
} bt_lmp_set_afh;

#define BT_LMP_ENCAPSULATED_HEADER 61
typedef struct __attribute__((packed)) {
  u8 major;
  u8 minor;
  u8 length;
} bt_lmp_encapsulated_header;

#define BT_LMP_ENCAPSULATED_PAYLOAD 62
typedef struct __attribute__((packed)) {
  u8 data[16];
} bt_lmp_encapsulated_payload;

#define BT_LMP_SIMPLE_PAIRING_CONFIRM 63
typedef struct __attribute__((packed)) {
  u8 value[16];
} bt_lmp_simple_pairing_confirm;

#define BT_LMP_SIMPLE_PAIRING_NUMBER 64
typedef struct __attribute__((packed)) {
  u8 value[16];
} bt_lmp_simple_pairing_number;

#define BT_LMP_DHKEY_CHECK 65
typedef struct __attribute__((packed)) {
  u8 value[16];
} bt_lmp_dhkey_check;

#define BT_LMP_PAUSE_ENCRYPTION_AES_REQ 66

#define BT_LMP_ACCEPTED_EXT LMP_ESC4(1)
typedef struct __attribute__((packed)) {
  u8 escape;
  u8 opcode;
} bt_lmp_accepted_ext;

#define BT_LMP_NOT_ACCEPTED_EXT LMP_ESC4(2)
typedef struct __attribute__((packed)) {
  u8 escape;
  u8 opcode;
  u8 error;
} bt_lmp_not_accepted_ext;

#define BT_LMP_FEATURES_REQ_EXT LMP_ESC4(3)
typedef struct __attribute__((packed)) {
  u8 page;
  u8 max_page;
  u8 features[8];
} bt_lmp_features_req_ext;

#define BT_LMP_FEATURES_RES_EXT LMP_ESC4(4)
typedef struct __attribute__((packed)) {
  u8 page;
  u8 max_page;
  u8 features[8];
} bt_lmp_features_res_ext;

#define BT_LMP_PACKET_TYPE_TABLE_REQ LMP_ESC4(11)
typedef struct __attribute__((packed)) {
  u8 table;
} bt_lmp_packet_type_table_req;

#define BT_LMP_CHANNEL_CLASSIFICATION_REQ LMP_ESC4(16)
typedef struct __attribute__((packed)) {
  u8 mode;
  u16 min_interval;
  u16 max_interval;
} bt_lmp_channel_classification_req;

#define BT_LMP_CHANNEL_CLASSIFICATION LMP_ESC4(17)
typedef struct __attribute__((packed)) {
  u8 classification[10];
} bt_lmp_channel_classification;

#define BT_LMP_PAUSE_ENCRYPTION_REQ LMP_ESC4(23)

#define BT_LMP_RESUME_ENCRYPTION_REQ LMP_ESC4(24)

#define BT_LMP_IO_CAPABILITY_REQ LMP_ESC4(25)
typedef struct __attribute__((packed)) {
  u8 capability;
  u8 oob_data;
  u8 authentication;
} bt_lmp_io_capability_req;

#define BT_LMP_IO_CAPABILITY_RES LMP_ESC4(26)
typedef struct __attribute__((packed)) {
  u8 capability;
  u8 oob_data;
  u8 authentication;
} bt_lmp_io_capability_res;

#define BT_LMP_NUMERIC_COMPARISON_FAILED LMP_ESC(27)

#define BT_LMP_PASSKEY_FAILED LMP_ESC4(28)

#define BT_LMP_OOB_FAILED LMP_ESC(29)

#define BT_LMP_POWER_CONTROL_REQ LMP_ESC4(31)
typedef struct __attribute__((packed)) {
  u8 request;
} bt_lmp_power_control_req;

#define BT_LMP_POWER_CONTROL_RES LMP_ESC4(32)
typedef struct __attribute__((packed)) {
  u8 response;
} bt_lmp_power_control_res;

#define BT_LMP_PING_REQ LMP_ESC4(33)

#define BT_LMP_PING_RES LMP_ESC4(34)

#define BT_H4_CMD_PKT 0x01
#define BT_H4_ACL_PKT 0x02
#define BT_H4_SCO_PKT 0x03
#define BT_H4_EVT_PKT 0x04
#define BT_H4_ISO_PKT 0x05

typedef struct  __attribute__((packed)){
  u16 opcode;
  u8 len;
  u8 param[];
} bt_hci_cmd_hdr;

typedef struct __attribute__((packed)) {
  u16 handle;
  u16 len;
  u8 data[];
} bt_hci_acl_hdr;

#define ACL_PB_MASK 0x03u
#define ACL_PB_CONT (0x01u << 12)
#define ACL_PB_FIRST (0x02u << 12)

typedef struct __attribute__((packed)) {
  u16 handle;
  u8 dlen;
} bt_hci_sco_hdr;

typedef struct __attribute__((packed)) {
  u16 handle;
  u16 dlen;
  u8 data[];
} bt_hci_iso_hdr;

typedef struct __attribute__((packed)) {
  u16 sn;
  u16 len;
  u8 data[];
} bt_hci_iso_data_start;

typedef struct __attribute__((packed)) {
  u8 opcode;
  u8 len;
  u8 param[];
} bt_hci_evt_hdr;

#define BT_HCI_CMD_NOP 0x0000

#define BT_HCI_CMD_INQUIRY 0x0401
typedef struct __attribute__((packed)) {
  u8 lap[3];
  u8 length;
  u8 num_resp;
} bt_hci_cmd_inquiry;

#define BT_HCI_CMD_INQUIRY_CANCEL 0x0402

#define BT_HCI_CMD_PERIODIC_INQUIRY 0x0403
typedef struct __attribute__((packed)) {
  u16 max_period;
  u16 min_period;
  u8 lap[3];
  u8 length;
  u8 num_resp;
} bt_hci_cmd_periodic_inquiry;

#define BT_HCI_CMD_EXIT_PERIODIC_INQUIRY 0x0404

#define BT_HCI_CMD_CREATE_CONN 0x0405
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u16 pkt_type;
  u8 pscan_rep_mode;
  u8 pscan_mode;
  u16 clock_offset;
  u8 role_switch;
} bt_hci_cmd_create_conn;

#define BT_HCI_CMD_DISCONNECT 0x0406
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 reason;
} bt_hci_cmd_disconnect;

#define BT_HCI_CMD_ADD_SCO_CONN 0x0407
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 pkt_type;
} bt_hci_cmd_add_sco_conn;

#define BT_HCI_CMD_CREATE_CONN_CANCEL 0x0408
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_create_conn_cancel;

#define BT_HCI_CMD_ACCEPT_CONN_REQUEST 0x0409
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 role;
} bt_hci_cmd_accept_conn_request;

#define BT_HCI_CMD_REJECT_CONN_REQUEST 0x040a
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 reason;
} bt_hci_cmd_reject_conn_request;

#define BT_HCI_CMD_LINK_KEY_REQUEST_REPLY 0x040b
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 link_key[16];
} bt_hci_cmd_link_key_request_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_link_key_request_reply;

#define BT_HCI_CMD_LINK_KEY_REQUEST_NEG_REPLY 0x040c
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_link_key_request_neg_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_link_key_request_neg_reply;

#define BT_HCI_CMD_PIN_CODE_REQUEST_REPLY 0x040d
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 pin_len;
  u8 pin_code[16];
} bt_hci_cmd_pin_code_request_reply;

#define BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY 0x040e
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_pin_code_request_neg_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_pin_code_request_neg_reply;

#define BT_HCI_CMD_CHANGE_CONN_PKT_TYPE 0x040f
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 pkt_type;
} bt_hci_cmd_change_conn_pkt_type;

#define BT_HCI_CMD_AUTH_REQUESTED 0x0411
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_auth_requested;

#define BT_HCI_CMD_SET_CONN_ENCRYPT 0x0413
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 encr_mode;
} bt_hci_cmd_set_conn_encrypt;

#define BT_HCI_CMD_CHANGE_CONN_LINK_KEY 0x0415
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_change_conn_link_key;

#define BT_HCI_CMD_LINK_KEY_SELECTION 0x0417
typedef struct __attribute__((packed)) {
  u8 key_flag;
} bt_hci_cmd_link_key_selection;

#define BT_HCI_CMD_REMOTE_NAME_REQUEST 0x0419
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_mode;
  u16 clock_offset;
} bt_hci_cmd_remote_name_request;

#define BT_HCI_CMD_REMOTE_NAME_REQUEST_CANCEL 0x041a
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_remote_name_request_cancel;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_remote_name_request_cancel;

#define BT_HCI_CMD_READ_REMOTE_FEATURES 0x041b
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_remote_features;

#define BT_HCI_CMD_READ_REMOTE_EXT_FEATURES 0x041c
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 page;
} bt_hci_cmd_read_remote_ext_features;

#define BT_HCI_CMD_READ_REMOTE_VERSION 0x041d
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_remote_version;

#define BT_HCI_CMD_READ_CLOCK_OFFSET 0x041f
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_clock_offset;

#define BT_HCI_CMD_READ_LMP_HANDLE 0x0420
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_lmp_handle;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 lmp_handle;
  u32 reserved;
} bt_hci_rsp_read_lmp_handle;

#define BT_HCI_CMD_SETUP_SYNC_CONN 0x0428
typedef struct __attribute__((packed)) {
  u16 handle;
  u32 tx_bandwidth;
  u32 rx_bandwidth;
  u16 max_latency;
  u16 voice_setting;
  u8 retrans_effort;
  u16 pkt_type;
} bt_hci_cmd_setup_sync_conn;

#define BT_HCI_CMD_ACCEPT_SYNC_CONN_REQUEST 0x0429
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u32 tx_bandwidth;
  u32 rx_bandwidth;
  u16 max_latency;
  u16 voice_setting;
  u8 retrans_effort;
  u16 pkt_type;
} bt_hci_cmd_accept_sync_conn_request;

#define BT_HCI_CMD_REJECT_SYNC_CONN_REQUEST 0x042a
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 reason;
} bt_hci_cmd_reject_sync_conn_request;

#define BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY 0x042b
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 capability;
  u8 oob_data;
  u8 authentication;
} bt_hci_cmd_io_capability_request_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_io_capability_request_reply;

#define BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY 0x042c
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_user_confirm_request_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_user_confirm_request_reply;

#define BT_HCI_CMD_USER_CONFIRM_REQUEST_NEG_REPLY 0x042d
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_user_confirm_request_neg_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_user_confirm_request_neg_reply;

#define BT_HCI_CMD_USER_PASSKEY_REQUEST_REPLY 0x042e
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u32 passkey;
} bt_hci_cmd_user_passkey_request_reply;

#define BT_HCI_CMD_USER_PASSKEY_REQUEST_NEG_REPLY 0x042f
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_user_passkey_request_neg_reply;

#define BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_REPLY 0x0430
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 hash[16];
  u8 randomizer[16];
} bt_hci_cmd_remote_oob_data_request_reply;

#define BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_NEG_REPLY 0x0433
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_remote_oob_data_request_neg_reply;

#define BT_HCI_CMD_IO_CAPABILITY_REQUEST_NEG_REPLY 0x0434
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 reason;
} bt_hci_cmd_io_capability_request_neg_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_io_capability_request_neg_reply;

#define BT_HCI_CMD_CREATE_PHY_LINK 0x0435
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 key_len;
  u8 key_type;
} bt_hci_cmd_create_phy_link;

#define BT_HCI_CMD_ACCEPT_PHY_LINK 0x0436
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 key_len;
  u8 key_type;
} bt_hci_cmd_accept_phy_link;

#define BT_HCI_CMD_DISCONN_PHY_LINK 0x0437
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 reason;
} bt_hci_cmd_disconn_phy_link;

#define BT_HCI_CMD_CREATE_LOGIC_LINK 0x0438
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 tx_flow_spec[16];
  u8 rx_flow_spec[16];
} bt_hci_cmd_create_logic_link;

#define BT_HCI_CMD_ACCEPT_LOGIC_LINK 0x0439
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 tx_flow_spec[16];
  u8 rx_flow_spec[16];
} bt_hci_cmd_accept_logic_link;

#define BT_HCI_CMD_DISCONN_LOGIC_LINK 0x043a
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_disconn_logic_link;

#define BT_HCI_CMD_LOGIC_LINK_CANCEL 0x043b
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 flow_spec;
} bt_hci_cmd_logic_link_cancel;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 phy_handle;
  u8 flow_spec;
} bt_hci_rsp_logic_link_cancel;

#define BT_HCI_CMD_FLOW_SPEC_MODIFY 0x043c
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 tx_flow_spec[16];
  u8 rx_flow_spec[16];
} bt_hci_cmd_flow_spec_modify;

#define BT_HCI_CMD_ENHANCED_SETUP_SYNC_CONN 0x043d
typedef struct __attribute__((packed)) {
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
} bt_hci_cmd_enhanced_setup_sync_conn;

#define BT_HCI_CMD_ENHANCED_ACCEPT_SYNC_CONN_REQUEST 0x043e
typedef struct __attribute__((packed)) {
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
} bt_hci_cmd_enhanced_accept_sync_conn_request;

#define BT_HCI_CMD_TRUNCATED_PAGE 0x043f
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u16 clock_offset;
} bt_hci_cmd_truncated_page;

#define BT_HCI_CMD_TRUNCATED_PAGE_CANCEL 0x0440
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_cmd_truncated_page_cancel;

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST 0x0441
typedef struct __attribute__((packed)) {
  u8 enable;
  u8 lt_addr;
  u8 lpo_allowed;
  u16 pkt_type;
  u16 min_interval;
  u16 max_interval;
  u16 timeout;
} bt_hci_cmd_set_peripheral_broadcast;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 lt_addr;
  u16 interval;
} bt_hci_rsp_set_peripheral_broadcast;

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_RECEIVE 0x0442
typedef struct __attribute__((packed)) {
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
} bt_hci_cmd_set_peripheral_broadcast_receive;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
  u8 lt_addr;
} bt_hci_rsp_set_peripheral_broadcast_receive;

#define BT_HCI_CMD_START_SYNC_TRAIN 0x0443

#define BT_HCI_CMD_RECEIVE_SYNC_TRAIN 0x0444
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u16 timeout;
  u16 window;
  u16 interval;
} bt_hci_cmd_receive_sync_train;

#define BT_HCI_CMD_REMOTE_OOB_EXT_DATA_REQUEST_REPLY 0x0445
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 hash192[16];
  u8 randomizer192[16];
  u8 hash256[16];
  u8 randomizer256[16];
} bt_hci_cmd_remote_oob_ext_data_request_reply;

#define BT_HCI_CMD_HOLD_MODE 0x0801
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 max_interval;
  u16 min_interval;
} bt_hci_cmd_hold_mode;

#define BT_HCI_CMD_SNIFF_MODE 0x0803
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 max_interval;
  u16 min_interval;
  u16 attempt;
  u16 timeout;
} bt_hci_cmd_sniff_mode;

#define BT_HCI_CMD_EXIT_SNIFF_MODE 0x0804
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_exit_sniff_mode;

#define BT_HCI_CMD_PARK_STATE 0x0805
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 max_interval;
  u16 min_interval;
} bt_hci_cmd_park_state;

#define BT_HCI_CMD_EXIT_PARK_STATE 0x0806
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_exit_park_state;

#define BT_HCI_CMD_QOS_SETUP 0x0807
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 flags;
  u8 service_type;
  u32 token_rate;
  u32 peak_bandwidth;
  u32 latency;
  u32 delay_variation;
} bt_hci_cmd_qos_setup;

#define BT_HCI_CMD_ROLE_DISCOVERY 0x0809
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_role_discovery;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 role;
} bt_hci_rsp_role_discovery;

#define BT_HCI_CMD_SWITCH_ROLE 0x080b
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 role;
} bt_hci_cmd_switch_role;

#define BT_HCI_CMD_READ_LINK_POLICY 0x080c
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_link_policy;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 policy;
} bt_hci_rsp_read_link_policy;

#define BT_HCI_CMD_WRITE_LINK_POLICY 0x080d
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 policy;
} bt_hci_cmd_write_link_policy;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_write_link_policy;

#define BT_HCI_CMD_READ_DEFAULT_LINK_POLICY 0x080e
typedef struct __attribute__((packed)) {
  u8 status;
  u16 policy;
} bt_hci_rsp_read_default_link_policy;

#define BT_HCI_CMD_WRITE_DEFAULT_LINK_POLICY 0x080f
typedef struct __attribute__((packed)) {
  u16 policy;
} bt_hci_cmd_write_default_link_policy;

#define BT_HCI_CMD_FLOW_SPEC 0x0810
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 flags;
  u8 direction;
  u8 service_type;
  u32 token_rate;
  u32 token_bucket_size;
  u32 peak_bandwidth;
  u32 access_latency;
} bt_hci_cmd_flow_spec;

#define BT_HCI_CMD_SNIFF_SUBRATING 0x0811
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 max_latency;
  u16 min_remote_timeout;
  u16 min_local_timeout;
} bt_hci_cmd_sniff_subrating;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_sniff_subrating;

#define BT_HCI_CMD_SET_EVENT_MASK 0x0c01
typedef struct __attribute__((packed)) {
  u8 mask[8];
} bt_hci_cmd_set_event_mask;

#define BT_HCI_CMD_RESET 0x0c03

#define BT_HCI_CMD_SET_EVENT_FILTER 0x0c05
typedef struct __attribute__((packed)) {
  u8 type;
  u8 cond_type;
  u8 cond[0];
} bt_hci_cmd_set_event_filter;

#define BT_HCI_CMD_FLUSH 0x0c08
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_flush;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_flush;

#define BT_HCI_CMD_READ_PIN_TYPE 0x0c09
typedef struct __attribute__((packed)) {
  u8 status;
  u8 pin_type;
} bt_hci_rsp_read_pin_type;

#define BT_HCI_CMD_WRITE_PIN_TYPE 0x0c0a
typedef struct __attribute__((packed)) {
  u8 pin_type;
} bt_hci_cmd_write_pin_type;

#define BT_HCI_CMD_CREATE_NEW_UNIT_KEY 0x0c0b

#define BT_HCI_CMD_READ_STORED_LINK_KEY 0x0c0d
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 read_all;
} bt_hci_cmd_read_stored_link_key;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 max_num_keys;
  u16 num_keys;
} bt_hci_rsp_read_stored_link_key;

#define BT_HCI_CMD_WRITE_STORED_LINK_KEY 0x0c11
typedef struct __attribute__((packed)) {
  u8 num_keys;
} bt_hci_cmd_write_stored_link_key;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_keys;
} bt_hci_rsp_write_stored_link_key;

#define BT_HCI_CMD_DELETE_STORED_LINK_KEY 0x0c12
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 delete_all;
} bt_hci_cmd_delete_stored_link_key;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 num_keys;
} bt_hci_rsp_delete_stored_link_key;

#define BT_HCI_CMD_WRITE_LOCAL_NAME 0x0c13
typedef struct __attribute__((packed)) {
  u8 name[248];
} bt_hci_cmd_write_local_name;

#define BT_HCI_CMD_READ_LOCAL_NAME 0x0c14
typedef struct __attribute__((packed)) {
  u8 status;
  char name[248];
} bt_hci_rsp_read_local_name;

#define BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT 0x0c15
typedef struct __attribute__((packed)) {
  u8 status;
  u16 timeout;
} bt_hci_rsp_read_conn_accept_timeout;

#define BT_HCI_CMD_WRITE_CONN_ACCEPT_TIMEOUT 0x0c16
typedef struct __attribute__((packed)) {
  u16 timeout;
} bt_hci_cmd_write_conn_accept_timeout;

#define BT_HCI_CMD_READ_PAGE_TIMEOUT 0x0c17
typedef struct __attribute__((packed)) {
  u8 status;
  u16 timeout;
} bt_hci_rsp_read_page_timeout;

#define BT_HCI_CMD_WRITE_PAGE_TIMEOUT 0x0c18
typedef struct __attribute__((packed)) {
  u16 timeout;
} bt_hci_cmd_write_page_timeout;

#define BT_HCI_CMD_READ_SCAN_ENABLE 0x0c19
typedef struct __attribute__((packed)) {
  u8 status;
  u8 enable;
} bt_hci_rsp_read_scan_enable;

#define BT_HCI_CMD_WRITE_SCAN_ENABLE 0x0c1a
typedef struct __attribute__((packed)) {
  u8 enable;
} bt_hci_cmd_write_scan_enable;

#define BT_HCI_CMD_READ_PAGE_SCAN_ACTIVITY 0x0c1b
typedef struct __attribute__((packed)) {
  u8 status;
  u16 interval;
  u16 window;
} bt_hci_rsp_read_page_scan_activity;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY 0x0c1c
typedef struct __attribute__((packed)) {
  u16 interval;
  u16 window;
} bt_hci_cmd_write_page_scan_activity;

#define BT_HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY 0x0c1d
typedef struct __attribute__((packed)) {
  u8 status;
  u16 interval;
  u16 window;
} bt_hci_rsp_read_inquiry_scan_activity;

#define BT_HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY 0x0c1e
typedef struct __attribute__((packed)) {
  u16 interval;
  u16 window;
} bt_hci_cmd_write_inquiry_scan_activity;

#define BT_HCI_CMD_READ_AUTH_ENABLE 0x0c1f
typedef struct __attribute__((packed)) {
  u8 status;
  u8 enable;
} bt_hci_rsp_read_auth_enable;

#define BT_HCI_CMD_WRITE_AUTH_ENABLE 0x0c20
typedef struct __attribute__((packed)) {
  u8 enable;
} bt_hci_cmd_write_auth_enable;

#define BT_HCI_CMD_READ_ENCRYPT_MODE 0x0c21
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_encrypt_mode;

#define BT_HCI_CMD_WRITE_ENCRYPT_MODE 0x0c22
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_encrypt_mode;

#define BT_HCI_CMD_READ_CLASS_OF_DEV 0x0c23
typedef struct __attribute__((packed)) {
  u8 status;
  u8 dev_class[3];
} bt_hci_rsp_read_class_of_dev;

#define BT_HCI_CMD_WRITE_CLASS_OF_DEV 0x0c24
typedef struct __attribute__((packed)) {
  u8 dev_class[3];
} bt_hci_cmd_write_class_of_dev;

#define BT_HCI_CMD_READ_VOICE_SETTING 0x0c25
typedef struct __attribute__((packed)) {
  u8 status;
  u16 setting;
} bt_hci_rsp_read_voice_setting;

#define BT_HCI_CMD_WRITE_VOICE_SETTING 0x0c26
typedef struct __attribute__((packed)) {
  u16 setting;
} bt_hci_cmd_write_voice_setting;

#define BT_HCI_CMD_READ_AUTO_FLUSH_TIMEOUT 0x0c27
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_auto_flush_timeout;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 timeout;
} bt_hci_rsp_read_auto_flush_timeout;

#define BT_HCI_CMD_WRITE_AUTO_FLUSH_TIMEOUT 0x0c28
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 timeout;
} bt_hci_cmd_write_auto_flush_timeout;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_write_auto_flush_timeout;

#define BT_HCI_CMD_READ_NUM_BROADCAST_RETRANS 0x0c29
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_retrans;
} bt_hci_rsp_read_num_broadcast_retrans;

#define BT_HCI_CMD_WRITE_NUM_BROADCAST_RETRANS 0x0c2a
typedef struct __attribute__((packed)) {
  u8 num_retrans;
} bt_hci_cmd_write_num_broadcast_retrans;

#define BT_HCI_CMD_READ_HOLD_MODE_ACTIVITY 0x0c2b
typedef struct __attribute__((packed)) {
  u8 status;
  u8 activity;
} bt_hci_rsp_read_hold_mode_activity;

#define BT_HCI_CMD_WRITE_HOLD_MODE_ACTIVITY 0x0c2c
typedef struct __attribute__((packed)) {
  u8 activity;
} bt_hci_cmd_write_hold_mode_activity;

#define BT_HCI_CMD_READ_TX_POWER 0x0c2d
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 type;
} bt_hci_cmd_read_tx_power;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  int8_t level;
} bt_hci_rsp_read_tx_power;

#define BT_HCI_CMD_READ_SYNC_FLOW_CONTROL 0x0c2e
typedef struct __attribute__((packed)) {
  u8 status;
  u8 enable;
} bt_hci_rsp_read_sync_flow_control;

#define BT_HCI_CMD_WRITE_SYNC_FLOW_CONTROL 0x0c2f
typedef struct __attribute__((packed)) {
  u8 enable;
} bt_hci_cmd_write_sync_flow_control;

#define BT_HCI_CMD_SET_HOST_FLOW_CONTROL 0x0c31
typedef struct __attribute__((packed)) {
  u8 enable;
} bt_hci_cmd_set_host_flow_control;

#define BT_HCI_CMD_HOST_BUFFER_SIZE 0x0c33
typedef struct __attribute__((packed)) {
  u16 acl_mtu;
  u8 sco_mtu;
  u16 acl_max_pkt;
  u16 sco_max_pkt;
} bt_hci_cmd_host_buffer_size;

#define BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS 0x0c35
typedef struct __attribute__((packed)) {
  u8 num_handles;
  u16 handle;
  u16 count;
} bt_hci_cmd_host_num_completed_packets;

#define BT_HCI_CMD_READ_LINK_SUPV_TIMEOUT 0x0c36
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_link_supv_timeout;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 timeout;
} bt_hci_rsp_read_link_supv_timeout;

#define BT_HCI_CMD_WRITE_LINK_SUPV_TIMEOUT 0x0c37
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 timeout;
} bt_hci_cmd_write_link_supv_timeout;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_write_link_supv_timeout;

#define BT_HCI_CMD_READ_NUM_SUPPORTED_IAC 0x0c38
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_iac;
} bt_hci_rsp_read_num_supported_iac;

#define BT_HCI_CMD_READ_CURRENT_IAC_LAP 0x0c39
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_iac;
  u8 iac_lap[0];
} bt_hci_rsp_read_current_iac_lap;

#define BT_HCI_CMD_WRITE_CURRENT_IAC_LAP 0x0c3a
typedef struct __attribute__((packed)) {
  u8 num_iac;
  u8 iac_lap[0];
} bt_hci_cmd_write_current_iac_lap;

#define BT_HCI_CMD_READ_PAGE_SCAN_PERIOD_MODE 0x0c3b
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_page_scan_period_mode;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_PERIOD_MODE 0x0c3c
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_page_scan_period_mode;

#define BT_HCI_CMD_READ_PAGE_SCAN_MODE 0x0c3d
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_page_scan_mode;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_MODE 0x0c3e
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_page_scan_mode;

#define BT_HCI_CMD_SET_AFH_HOST_CLASSIFICATION 0x0c3f
typedef struct __attribute__((packed)) {
  u8 map[10];
} bt_hci_cmd_set_afh_host_classification;

#define BT_HCI_CMD_READ_INQUIRY_SCAN_TYPE 0x0c42
typedef struct __attribute__((packed)) {
  u8 status;
  u8 type;
} bt_hci_rsp_read_inquiry_scan_type;

#define BT_HCI_CMD_WRITE_INQUIRY_SCAN_TYPE 0x0c43
typedef struct __attribute__((packed)) {
  u8 type;
} bt_hci_cmd_write_inquiry_scan_type;

#define BT_HCI_CMD_READ_INQUIRY_MODE 0x0c44
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_inquiry_mode;

#define BT_HCI_CMD_WRITE_INQUIRY_MODE 0x0c45
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_inquiry_mode;

#define BT_HCI_CMD_READ_PAGE_SCAN_TYPE 0x0c46
typedef struct __attribute__((packed)) {
  u8 status;
  u8 type;
} bt_hci_rsp_read_page_scan_type;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_TYPE 0x0c47
typedef struct __attribute__((packed)) {
  u8 type;
} bt_hci_cmd_write_page_scan_type;

#define BT_HCI_CMD_READ_AFH_ASSESSMENT_MODE 0x0c48
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_afh_assessment_mode;

#define BT_HCI_CMD_WRITE_AFH_ASSESSMENT_MODE 0x0c49
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_afh_assessment_mode;

#define BT_HCI_CMD_READ_EXT_INQUIRY_RESPONSE 0x0c51
typedef struct __attribute__((packed)) {
  u8 status;
  u8 fec;
  u8 data[240];
} bt_hci_rsp_read_ext_inquiry_response;

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE 0x0c52
typedef struct __attribute__((packed)) {
  u8 fec;
  u8 data[240];
} bt_hci_cmd_write_ext_inquiry_response;

#define BT_HCI_CMD_REFRESH_ENCRYPT_KEY 0x0c53
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_refresh_encrypt_key;

#define BT_HCI_CMD_READ_SIMPLE_PAIRING_MODE 0x0c55
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_simple_pairing_mode;

#define BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE 0x0c56
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_simple_pairing_mode;

#define BT_HCI_CMD_READ_LOCAL_OOB_DATA 0x0c57
typedef struct __attribute__((packed)) {
  u8 status;
  u8 hash[16];
  u8 randomizer[16];
} bt_hci_rsp_read_local_oob_data;

#define BT_HCI_CMD_READ_INQUIRY_RESP_TX_POWER 0x0c58
typedef struct __attribute__((packed)) {
  u8 status;
  int8_t level;
} bt_hci_rsp_read_inquiry_resp_tx_power;

#define BT_HCI_CMD_WRITE_INQUIRY_TX_POWER 0x0c59
typedef struct __attribute__((packed)) {
  int8_t level;
} bt_hci_cmd_write_inquiry_tx_power;

#define BT_HCI_CMD_READ_ERRONEOUS_REPORTING 0x0c5a
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_erroneous_reporting;

#define BT_HCI_CMD_WRITE_ERRONEOUS_REPORTING 0x0c5b
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_erroneous_reporting;

#define BT_HCI_CMD_ENHANCED_FLUSH 0x0c5f
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 type;
} bt_hci_cmd_enhanced_flush;

#define BT_HCI_CMD_SEND_KEYPRESS_NOTIFY 0x0c60
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 type;
} bt_hci_cmd_send_keypress_notify;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_send_keypress_notify;

#define BT_HCI_CMD_SET_EVENT_MASK_PAGE2 0x0c63
typedef struct __attribute__((packed)) {
  u8 mask[8];
} bt_hci_cmd_set_event_mask_page2;

#define BT_HCI_CMD_READ_LOCATION_DATA 0x0c64
typedef struct __attribute__((packed)) {
  u8 status;
  u8 domain_aware;
  u8 domain[2];
  u8 domain_options;
  u8 options;
} bt_hci_rsp_read_location_data;

#define BT_HCI_CMD_WRITE_LOCATION_DATA 0x0c65
typedef struct __attribute__((packed)) {
  u8 domain_aware;
  u8 domain[2];
  u8 domain_options;
  u8 options;
} bt_hci_cmd_write_location_data;

#define BT_HCI_CMD_READ_FLOW_CONTROL_MODE 0x0c66
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_flow_control_mode;

#define BT_HCI_CMD_WRITE_FLOW_CONTROL_MODE 0x0c67
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_flow_control_mode;

#define BT_HCI_CMD_READ_ENHANCED_TX_POWER 0x0c68
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 type;
} bt_hci_cmd_read_enhanced_tx_power;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  int8_t level_gfsk;
  int8_t level_dqpsk;
  int8_t level_8dpsk;
} bt_hci_rsp_read_enhanced_tx_power;

#define BT_HCI_CMD_SHORT_RANGE_MODE 0x0c6b
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 mode;
} bt_hci_cmd_short_range_mode;

#define BT_HCI_CMD_READ_LE_HOST_SUPPORTED 0x0c6c
typedef struct __attribute__((packed)) {
  u8 status;
  u8 supported;
  u8 simultaneous;
} bt_hci_rsp_read_le_host_supported;

#define BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED 0x0c6d
typedef struct __attribute__((packed)) {
  u8 supported;
  u8 simultaneous;
} bt_hci_cmd_write_le_host_supported;

#define BT_HCI_CMD_SET_RESERVED_LT_ADDR 0x0c74
typedef struct __attribute__((packed)) {
  u8 lt_addr;
} bt_hci_cmd_set_reserved_lt_addr;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 lt_addr;
} bt_hci_rsp_set_reserved_lt_addr;

#define BT_HCI_CMD_DELETE_RESERVED_LT_ADDR 0x0c75
typedef struct __attribute__((packed)) {
  u8 lt_addr;
} bt_hci_cmd_delete_reserved_lt_addr;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 lt_addr;
} bt_hci_rsp_delete_reserved_lt_addr;

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_DATA 0x0c76
typedef struct __attribute__((packed)) {
  u8 lt_addr;
  u8 fragment;
  u8 length;
} bt_hci_cmd_set_peripheral_broadcast_data;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 lt_addr;
} bt_hci_rsp_set_peripheral_broadcast_data;

#define BT_HCI_CMD_READ_SYNC_TRAIN_PARAMS 0x0c77
typedef struct __attribute__((packed)) {
  u8 status;
  u16 interval;
  u32 timeout;
  u8 service_data;
} bt_hci_rsp_read_sync_train_params;

#define BT_HCI_CMD_WRITE_SYNC_TRAIN_PARAMS 0x0c78
typedef struct __attribute__((packed)) {
  u16 min_interval;
  u16 max_interval;
  u32 timeout;
  u8 service_data;
} bt_hci_cmd_write_sync_train_params;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 interval;
} bt_hci_rsp_write_sync_train_params;

#define BT_HCI_CMD_READ_SECURE_CONN_SUPPORT 0x0c79
typedef struct __attribute__((packed)) {
  u8 status;
  u8 support;
} bt_hci_rsp_read_secure_conn_support;

#define BT_HCI_CMD_WRITE_SECURE_CONN_SUPPORT 0x0c7a
typedef struct __attribute__((packed)) {
  u8 support;
} bt_hci_cmd_write_secure_conn_support;

#define BT_HCI_CMD_READ_AUTH_PAYLOAD_TIMEOUT 0x0c7b
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_auth_payload_timeout;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 timeout;
} bt_hci_rsp_read_auth_payload_timeout;

#define BT_HCI_CMD_WRITE_AUTH_PAYLOAD_TIMEOUT 0x0c7c
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 timeout;
} bt_hci_cmd_write_auth_payload_timeout;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_write_auth_payload_timeout;

#define BT_HCI_CMD_READ_LOCAL_OOB_EXT_DATA 0x0c7d
typedef struct __attribute__((packed)) {
  u8 status;
  u8 hash192[16];
  u8 randomizer192[16];
  u8 hash256[16];
  u8 randomizer256[16];
} bt_hci_rsp_read_local_oob_ext_data;

#define BT_HCI_CMD_READ_EXT_PAGE_TIMEOUT 0x0c7e
typedef struct __attribute__((packed)) {
  u8 status;
  u16 timeout;
} bt_hci_rsp_read_ext_page_timeout;

#define BT_HCI_CMD_WRITE_EXT_PAGE_TIMEOUT 0x0c7f
typedef struct __attribute__((packed)) {
  u16 timeout;
} bt_hci_cmd_write_ext_page_timeout;

#define BT_HCI_CMD_READ_EXT_INQUIRY_LENGTH 0x0c80
typedef struct __attribute__((packed)) {
  u8 status;
  u16 interval;
} bt_hci_rsp_read_ext_inquiry_length;

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_LENGTH 0x0c81
typedef struct __attribute__((packed)) {
  u16 interval;
} bt_hci_cmd_write_ext_inquiry_length;

#define BT_HCI_CMD_CONFIG_DATA_PATH 0x0c83
#define BT_HCI_BIT_CONFIG_DATA_PATH BT_HCI_CMD_BIT(45, 5)
typedef struct __attribute__((packed)) {
  u8 dir;
  u8 id;
  u8 vnd_config_len;
  u8 vnd_config[0];
} bt_hci_cmd_config_data_path;

#define BT_HCI_CMD_READ_LOCAL_VERSION 0x1001
typedef struct __attribute__((packed)) {
  u8 status;
  u8 hci_ver;
  u16 hci_rev;
  u8 lmp_ver;
  u16 manufacturer;
  u16 lmp_subver;
} bt_hci_rsp_read_local_version;

#define BT_HCI_CMD_READ_LOCAL_COMMANDS 0x1002
typedef struct __attribute__((packed)) {
  u8 status;
  u8 commands[64];
} bt_hci_rsp_read_local_commands;

#define BT_HCI_CMD_READ_LOCAL_FEATURES 0x1003
typedef struct __attribute__((packed)) {
  u8 status;
  u8 features[8];
} bt_hci_rsp_read_local_features;

#define BT_HCI_CMD_READ_LOCAL_EXT_FEATURES 0x1004
typedef struct __attribute__((packed)) {
  u8 page;
} bt_hci_cmd_read_local_ext_features;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 page;
  u8 max_page;
  u8 features[8];
} bt_hci_rsp_read_local_ext_features;

#define BT_HCI_CMD_READ_BUFFER_SIZE 0x1005
typedef struct __attribute__((packed)) {
  u8 status;
  u16 acl_mtu;
  u8 sco_mtu;
  u16 acl_max_pkt;
  u16 sco_max_pkt;
} bt_hci_rsp_read_buffer_size;

#define BT_HCI_CMD_READ_COUNTRY_CODE 0x1007
typedef struct __attribute__((packed)) {
  u8 status;
  u8 code;
} bt_hci_rsp_read_country_code;

#define BT_HCI_CMD_READ_BD_ADDR 0x1009
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_rsp_read_bd_addr;

#define BT_HCI_CMD_READ_DATA_BLOCK_SIZE 0x100a
typedef struct __attribute__((packed)) {
  u8 status;
  u16 max_acl_len;
  u16 block_len;
  u16 num_blocks;
} bt_hci_rsp_read_data_block_size;

#define BT_HCI_CMD_READ_LOCAL_CODECS 0x100b
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_codecs;
  u8 codec[0];
} bt_hci_rsp_read_local_codecs;

#define BT_HCI_CMD_READ_LOCAL_PAIRING_OPTIONS 0x100c
typedef struct __attribute__((packed)) {
  u8 status;
  u8 pairing_options;
  u8 max_key_size;
} bt_hci_rsp_read_local_pairing_options;

#define BT_HCI_CMD_READ_LOCAL_CODECS_V2 0x100d
#define BT_HCI_BIT_READ_LOCAL_CODECS_V2 BT_HCI_CMD_BIT(45, 2)
#define BT_HCI_LOCAL_CODEC_BREDR_ACL BIT(0)
#define BT_HCI_LOCAL_CODEC_BREDR_SCO BIT(1)
#define BT_HCI_LOCAL_CODEC_LE_CIS BIT(2)
#define BT_HCI_LOCAL_CODEC_LE_BIS BIT(3)

typedef struct __attribute__((packed)) {
  u8 id;
  u16 cid;
  u16 vid;
  u8 transport;
} bt_hci_vnd_codec;

typedef struct __attribute__((packed)) {
  u8 id;
  u8 transport;
} bt_hci_codec;

typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_codecs;
  bt_hci_codec codec[0];
} bt_hci_rsp_read_local_codecs_v2;

#define BT_HCI_CMD_READ_LOCAL_CODEC_CAPS 0x100e
#define BT_HCI_BIT_READ_LOCAL_CODEC_CAPS BT_HCI_CMD_BIT(45, 3)
typedef struct __attribute__((packed)) {
  bt_hci_vnd_codec codec;
  u8 dir;
} bt_hci_cmd_read_local_codec_caps;

typedef struct __attribute__((packed)) {
  u8 len;
  u8 data[0];
} bt_hci_codec_caps;

typedef struct __attribute__((packed)) {
  u8 status;
  u8 num;
  bt_hci_codec_caps caps[0];
} bt_hci_rsp_read_local_codec_caps;

#define BT_HCI_CMD_READ_LOCAL_CTRL_DELAY 0x100f
#define BT_HCI_BIT_READ_LOCAL_CTRL_DELAY BT_HCI_CMD_BIT(45, 4)
typedef struct __attribute__((packed)) {
  bt_hci_vnd_codec codec;
  u8 dir;
  u8 codec_cfg_len;
  u8 codec_cfg[0];
} bt_hci_cmd_read_local_ctrl_delay;

typedef struct __attribute__((packed)) {
  u8 status;
  u8 min_delay[3];
  u8 max_delay[3];
} bt_hci_rsp_read_local_ctrl_delay;

#define BT_HCI_CMD_READ_FAILED_CONTACT_COUNTER 0x1401
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_failed_contact_counter;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 counter;
} bt_hci_rsp_read_failed_contact_counter;

#define BT_HCI_CMD_RESET_FAILED_CONTACT_COUNTER 0x1402
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_reset_failed_contact_counter;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_reset_failed_contact_counter;

#define BT_HCI_CMD_READ_LINK_QUALITY 0x1403
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_link_quality;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 link_quality;
} bt_hci_rsp_read_link_quality;

#define BT_HCI_CMD_READ_RSSI 0x1405
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_rssi;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  int8_t rssi;
} bt_hci_rsp_read_rssi;

#define BT_HCI_CMD_READ_AFH_CHANNEL_MAP 0x1406
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_afh_channel_map;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 mode;
  u8 map[10];
} bt_hci_rsp_read_afh_channel_map;

#define BT_HCI_CMD_READ_CLOCK 0x1407
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 type;
} bt_hci_cmd_read_clock;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u32 clock;
  u16 accuracy;
} bt_hci_rsp_read_clock;

#define BT_HCI_CMD_READ_ENCRYPT_KEY_SIZE 0x1408
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_read_encrypt_key_size;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 key_size;
} bt_hci_rsp_read_encrypt_key_size;

#define BT_HCI_CMD_READ_LOCAL_AMP_INFO 0x1409
typedef struct __attribute__((packed)) {
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
} bt_hci_rsp_read_local_amp_info;

#define BT_HCI_CMD_READ_LOCAL_AMP_ASSOC 0x140a
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u16 len_so_far;
  u16 max_assoc_len;
} bt_hci_cmd_read_local_amp_assoc;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 phy_handle;
  u16 remain_assoc_len;
  u8 assoc_fragment[248];
} bt_hci_rsp_read_local_amp_assoc;

#define BT_HCI_CMD_WRITE_REMOTE_AMP_ASSOC 0x140b
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u16 len_so_far;
  u16 remain_assoc_len;
  u8 assoc_fragment[248];
} bt_hci_cmd_write_remote_amp_assoc;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 phy_handle;
} bt_hci_rsp_write_remote_amp_assoc;

#define BT_HCI_CMD_GET_MWS_TRANSPORT_CONFIG 0x140c
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_transports;
  u8 transport[0];
} bt_hci_rsp_get_mws_transport_config;

#define BT_HCI_CMD_SET_TRIGGERED_CLOCK_CAPTURE 0x140d
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 enable;
  u8 type;
  u8 lpo_allowed;
  u8 num_filter;
} bt_hci_cmd_set_triggered_clock_capture;

#define BT_HCI_CMD_READ_LOOPBACK_MODE 0x1801
typedef struct __attribute__((packed)) {
  u8 status;
  u8 mode;
} bt_hci_rsp_read_loopback_mode;

#define BT_HCI_CMD_WRITE_LOOPBACK_MODE 0x1802
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_loopback_mode;

#define BT_HCI_CMD_ENABLE_DUT_MODE 0x1803

#define BT_HCI_CMD_WRITE_SSP_DEBUG_MODE 0x1804
typedef struct __attribute__((packed)) {
  u8 mode;
} bt_hci_cmd_write_ssp_debug_mode;

#define BT_HCI_CMD_LE_SET_EVENT_MASK 0x2001
typedef struct __attribute__((packed)) {
  u8 mask[8];
} bt_hci_cmd_le_set_event_mask;

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE 0x2002
typedef struct __attribute__((packed)) {
  u8 status;
  u16 le_mtu;
  u8 le_max_pkt;
} bt_hci_rsp_le_read_buffer_size;

#define BT_HCI_CMD_LE_READ_LOCAL_FEATURES 0x2003
typedef struct __attribute__((packed)) {
  u8 status;
  u8 features[8];
} bt_hci_rsp_le_read_local_features;

#define BT_HCI_CMD_LE_SET_RANDOM_ADDRESS 0x2005
typedef struct __attribute__((packed)) {
  u8 addr[6];
} bt_hci_cmd_le_set_random_address;

#define BT_HCI_CMD_LE_SET_ADV_PARAMETERS 0x2006
typedef struct __attribute__((packed)) {
  u16 min_interval;
  u16 max_interval;
  u8 type;
  u8 own_addr_type;
  u8 direct_addr_type;
  u8 direct_addr[6];
  u8 channel_map;
  u8 filter_policy;
} bt_hci_cmd_le_set_adv_parameters;

#define BT_HCI_CMD_LE_READ_ADV_TX_POWER 0x2007
typedef struct __attribute__((packed)) {
  u8 status;
  int8_t level;
} bt_hci_rsp_le_read_adv_tx_power;

#define BT_HCI_CMD_LE_SET_ADV_DATA 0x2008
typedef struct __attribute__((packed)) {
  u8 len;
  u8 data[31];
} bt_hci_cmd_le_set_adv_data;

#define BT_HCI_CMD_LE_SET_SCAN_RSP_DATA 0x2009
typedef struct __attribute__((packed)) {
  u8 len;
  u8 data[31];
} bt_hci_cmd_le_set_scan_rsp_data;

#define BT_HCI_CMD_LE_SET_ADV_ENABLE 0x200a
typedef struct __attribute__((packed)) {
  u8 enable;
} bt_hci_cmd_le_set_adv_enable;

#define BT_HCI_CMD_LE_SET_SCAN_PARAMETERS 0x200b
typedef struct __attribute__((packed)) {
  u8 type;
  u16 interval;
  u16 window;
  u8 own_addr_type;
  u8 filter_policy;
} bt_hci_cmd_le_set_scan_parameters;

#define BT_HCI_CMD_LE_SET_SCAN_ENABLE 0x200c
typedef struct __attribute__((packed)) {
  u8 enable;
  u8 filter_dup;
} bt_hci_cmd_le_set_scan_enable;

#define BT_HCI_CMD_LE_CREATE_CONN 0x200d
typedef struct __attribute__((packed)) {
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
} bt_hci_cmd_le_create_conn;

#define BT_HCI_CMD_LE_CREATE_CONN_CANCEL 0x200e

#define BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE 0x200f
typedef struct __attribute__((packed)) {
  u8 status;
  u8 size;
} bt_hci_rsp_le_read_accept_list_size;

#define BT_HCI_CMD_LE_CLEAR_ACCEPT_LIST 0x2010

#define BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST 0x2011
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
} bt_hci_cmd_le_add_to_accept_list;

#define BT_HCI_CMD_LE_REMOVE_FROM_ACCEPT_LIST 0x2012
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
} bt_hci_cmd_le_remove_from_accept_list;

#define BT_HCI_CMD_LE_CONN_UPDATE 0x2013
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} bt_hci_cmd_le_conn_update;

#define BT_HCI_CMD_LE_SET_HOST_CLASSIFICATION 0x2014
typedef struct __attribute__((packed)) {
  u8 map[5];
} bt_hci_cmd_le_set_host_classification;

#define BT_HCI_CMD_LE_READ_CHANNEL_MAP 0x2015
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_read_channel_map;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 map[5];
} bt_hci_rsp_le_read_channel_map;

#define BT_HCI_CMD_LE_READ_REMOTE_FEATURES 0x2016
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_read_remote_features;

#define BT_HCI_CMD_LE_ENCRYPT 0x2017
typedef struct __attribute__((packed)) {
  u8 key[16];
  u8 plaintext[16];
} bt_hci_cmd_le_encrypt;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 data[16];
} bt_hci_rsp_le_encrypt;

#define BT_HCI_CMD_LE_RAND 0x2018
typedef struct __attribute__((packed)) {
  u8 status;
  u64 number;
} bt_hci_rsp_le_rand;

#define BT_HCI_CMD_LE_START_ENCRYPT 0x2019
typedef struct __attribute__((packed)) {
  u16 handle;
  u64 rand;
  u16 ediv;
  u8 ltk[16];
} bt_hci_cmd_le_start_encrypt;

#define BT_HCI_CMD_LE_LTK_REQ_REPLY 0x201a
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 ltk[16];
} bt_hci_cmd_le_ltk_req_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_le_ltk_req_reply;

#define BT_HCI_CMD_LE_LTK_REQ_NEG_REPLY 0x201b
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_ltk_req_neg_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_le_ltk_req_neg_reply;

#define BT_HCI_CMD_LE_READ_SUPPORTED_STATES 0x201c
typedef struct __attribute__((packed)) {
  u8 status;
  u8 states[8];
} bt_hci_rsp_le_read_supported_states;

#define BT_HCI_CMD_LE_RECEIVER_TEST 0x201d
typedef struct __attribute__((packed)) {
  u8 frequency;
} bt_hci_cmd_le_receiver_test;

#define BT_HCI_CMD_LE_TRANSMITTER_TEST 0x201e
typedef struct __attribute__((packed)) {
  u8 frequency;
  u8 data_len;
  u8 payload;
} bt_hci_cmd_le_transmitter_test;

#define BT_HCI_CMD_LE_TEST_END 0x201f
typedef struct __attribute__((packed)) {
  u8 status;
  u16 num_packets;
} bt_hci_rsp_le_test_end;

#define BT_HCI_CMD_LE_CONN_PARAM_REQ_REPLY 0x2020
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} bt_hci_cmd_le_conn_param_req_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_le_conn_param_req_reply;

#define BT_HCI_CMD_LE_CONN_PARAM_REQ_NEG_REPLY 0x2021
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 reason;
} bt_hci_cmd_le_conn_param_req_neg_reply;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_le_conn_param_req_neg_reply;

#define BT_HCI_CMD_LE_SET_DATA_LENGTH 0x2022
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 tx_len;
  u16 tx_time;
} bt_hci_cmd_le_set_data_length;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_le_set_data_length;

#define BT_HCI_CMD_LE_READ_DEFAULT_DATA_LENGTH 0x2023
typedef struct __attribute__((packed)) {
  u8 status;
  u16 tx_len;
  u16 tx_time;
} bt_hci_rsp_le_read_default_data_length;

#define BT_HCI_CMD_LE_WRITE_DEFAULT_DATA_LENGTH 0x2024
typedef struct __attribute__((packed)) {
  u16 tx_len;
  u16 tx_time;
} bt_hci_cmd_le_write_default_data_length;

#define BT_HCI_CMD_LE_READ_LOCAL_PK256 0x2025

#define BT_HCI_CMD_LE_GENERATE_DHKEY 0x2026
typedef struct __attribute__((packed)) {
  u8 remote_pk256[64];
} bt_hci_cmd_le_generate_dhkey;

#define BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST 0x2027
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
  u8 peer_irk[16];
  u8 local_irk[16];
} bt_hci_cmd_le_add_to_resolv_list;

#define BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST 0x2028
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
} bt_hci_cmd_le_remove_from_resolv_list;

#define BT_HCI_CMD_LE_CLEAR_RESOLV_LIST 0x2029

#define BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE 0x202a
typedef struct __attribute__((packed)) {
  u8 status;
  u8 size;
} bt_hci_rsp_le_read_resolv_list_size;

#define BT_HCI_CMD_LE_READ_PEER_RESOLV_ADDR 0x202b
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
} bt_hci_cmd_le_read_peer_resolv_addr;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 addr[6];
} bt_hci_rsp_le_read_peer_resolv_addr;

#define BT_HCI_CMD_LE_READ_LOCAL_RESOLV_ADDR 0x202c
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
} bt_hci_cmd_le_read_local_resolv_addr;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 addr[6];
} bt_hci_rsp_le_read_local_resolv_addr;

#define BT_HCI_CMD_LE_SET_RESOLV_ENABLE 0x202d
typedef struct __attribute__((packed)) {
  u8 enable;
} bt_hci_cmd_le_set_resolv_enable;

#define BT_HCI_CMD_LE_SET_RESOLV_TIMEOUT 0x202e
typedef struct __attribute__((packed)) {
  u16 timeout;
} bt_hci_cmd_le_set_resolv_timeout;

#define BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH 0x202f
typedef struct __attribute__((packed)) {
  u8 status;
  u16 max_tx_len;
  u16 max_tx_time;
  u16 max_rx_len;
  u16 max_rx_time;
} bt_hci_rsp_le_read_max_data_length;

#define BT_HCI_CMD_LE_READ_PHY 0x2030
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_read_phy;
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 tx_phy;
  u8 rx_phy;
} bt_hci_rsp_le_read_phy;

#define BT_HCI_CMD_LE_SET_DEFAULT_PHY 0x2031
typedef struct __attribute__((packed)) {
  u8 all_phys;
  u8 tx_phys;
  u8 rx_phys;
} bt_hci_cmd_le_set_default_phy;

#define BT_HCI_CMD_LE_SET_PHY 0x2032
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 all_phys;
  u8 tx_phys;
  u8 rx_phys;
  u16 phy_opts;
} bt_hci_cmd_le_set_phy;

#define BT_HCI_CMD_LE_ENHANCED_RECEIVER_TEST 0x2033
typedef struct __attribute__((packed)) {
  u8 rx_channel;
  u8 phy;
  u8 modulation_index;
} bt_hci_cmd_le_enhanced_receiver_test;

#define BT_HCI_CMD_LE_ENHANCED_TRANSMITTER_TEST 0x2034
typedef struct __attribute__((packed)) {
  u8 tx_channel;
  u8 data_len;
  u8 payload;
  u8 phy;
} bt_hci_cmd_le_enhanced_transmitter_test;

#define BT_HCI_CMD_LE_SET_ADV_SET_RAND_ADDR 0x2035
typedef struct __attribute__((packed)) {
  u8 handle;
  u8 bdaddr[6];
} bt_hci_cmd_le_set_adv_set_rand_addr;

#define BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS 0x2036
typedef struct __attribute__((packed)) {
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
} bt_hci_cmd_le_set_ext_adv_params;
typedef struct __attribute__((packed)) {
  u8 status;
  u8 tx_power;
} bt_hci_rsp_le_set_ext_adv_params;

#define BT_HCI_CMD_LE_SET_EXT_ADV_DATA 0x2037
typedef struct __attribute__((packed)) {
  u8 handle;
  u8 operation;
  u8 fragment_preference;
  u8 data_len;
  u8 data[0];
} bt_hci_cmd_le_set_ext_adv_data;

#define BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA 0x2038
typedef struct __attribute__((packed)) {
  u8 handle;
  u8 operation;
  u8 fragment_preference;
  u8 data_len;
  u8 data[0];
} bt_hci_cmd_le_set_ext_scan_rsp_data;

#define BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE 0x2039
typedef struct __attribute__((packed)) {
  u8 enable;
  u8 num_of_sets;
} bt_hci_cmd_le_set_ext_adv_enable;
typedef struct __attribute__((packed)) {
  u8 handle;
  u16 duration;
  u8 max_events;
} bt_hci_cmd_ext_adv_set;

#define BT_HCI_CMD_LE_READ_MAX_ADV_DATA_LEN 0x203a
typedef struct __attribute__((packed)) {
  u8 status;
  u16 max_len;
} bt_hci_rsp_le_read_max_adv_data_len;

#define BT_HCI_CMD_LE_READ_NUM_SUPPORTED_ADV_SETS 0x203b
typedef struct __attribute__((packed)) {
  u8 status;
  u8 num_of_sets;
} bt_hci_rsp_le_read_num_supported_adv_sets;

#define BT_HCI_CMD_LE_REMOVE_ADV_SET 0x203c
typedef struct __attribute__((packed)) {
  u8 handle;
} bt_hci_cmd_le_remove_adv_set;

#define BT_HCI_CMD_LE_CLEAR_ADV_SETS 0x203d

#define BT_HCI_CMD_LE_SET_PA_PARAMS 0x203e
typedef struct __attribute__((packed)) {
  u8 handle;
  u16 min_interval;
  u16 max_interval;
  u16 properties;
} bt_hci_cmd_le_set_pa_params;

#define BT_HCI_CMD_LE_SET_PA_DATA 0x203f
typedef struct __attribute__((packed)) {
  u8 handle;
  u8 operation;
  u8 data_len;
  u8 data[0];
} bt_hci_cmd_le_set_pa_data;

#define BT_HCI_CMD_LE_SET_PA_ENABLE 0x2040
typedef struct __attribute__((packed)) {
  u8 enable;
  u8 handle;
} bt_hci_cmd_le_set_pa_enable;

#define BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS 0x2041
typedef struct __attribute__((packed)) {
  u8 own_addr_type;
  u8 filter_policy;
  u8 num_phys;
  u8 data[0];
} bt_hci_cmd_le_set_ext_scan_params;
typedef struct __attribute__((packed)) {
  u8 type;
  u16 interval;
  u16 window;
} bt_hci_le_scan_phy;

#define BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE 0x2042
typedef struct __attribute__((packed)) {
  u8 enable;
  u8 filter_dup;
  u16 duration;
  u16 period;
} bt_hci_cmd_le_set_ext_scan_enable;

#define BT_HCI_CMD_LE_EXT_CREATE_CONN 0x2043
typedef struct __attribute__((packed)) {
  u8 filter_policy;
  u8 own_addr_type;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u8 phys;
  u8 data[0];
} bt_hci_cmd_le_ext_create_conn;
typedef struct __attribute__((packed)) {
  u16 scan_interval;
  u16 scan_window;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
  u16 min_length;
  u16 max_length;
} bt_hci_le_ext_create_conn;

#define BT_HCI_CMD_LE_PA_CREATE_SYNC 0x2044
typedef struct __attribute__((packed)) {
  u8 options;
  u8 sid;
  u8 addr_type;
  u8 addr[6];
  u16 skip;
  u16 sync_timeout;
  u8 sync_cte_type;
} bt_hci_cmd_le_pa_create_sync;

#define BT_HCI_CMD_LE_PA_CREATE_SYNC_CANCEL 0x2045

#define BT_HCI_CMD_LE_PA_TERM_SYNC 0x2046
typedef struct __attribute__((packed)) {
  u16 sync_handle;
} bt_hci_cmd_le_pa_term_sync;

#define BT_HCI_CMD_LE_ADD_DEV_PA_LIST 0x2047
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
  u8 sid;
} bt_hci_cmd_le_add_dev_pa_list;

#define BT_HCI_CMD_LE_REMOVE_DEV_PA_LIST 0x2048
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
  u8 sid;
} bt_hci_cmd_le_remove_dev_pa_list;

#define BT_HCI_CMD_LE_CLEAR_PA_LIST 0x2049

#define BT_HCI_CMD_LE_READ_PA_LIST_SIZE 0x204a
typedef struct __attribute__((packed)) {
  u8 status;
  u8 list_size;
} bt_hci_rsp_le_read_dev_pa_list_size;

#define BT_HCI_CMD_LE_READ_TX_POWER 0x204b
typedef struct __attribute__((packed)) {
  u8 status;
  int8_t min_tx_power;
  int8_t max_tx_power;
} bt_hci_rsp_le_read_tx_power;

#define BT_HCI_CMD_LE_READ_RF_PATH_COMPENSATION 0x204c
typedef struct __attribute__((packed)) {
  u8 status;
  u16 rf_tx_path_comp;
  u16 rf_rx_path_comp;
} bt_hci_rsp_le_read_rf_path_comp;

#define BT_HCI_CMD_LE_WRITE_RF_PATH_COMPENSATION 0x204d
typedef struct __attribute__((packed)) {
  u16 rf_tx_path_comp;
  u16 rf_rx_path_comp;
} bt_hci_cmd_le_write_rf_path_comp;

#define BT_HCI_CMD_LE_SET_PRIV_MODE 0x204e
typedef struct __attribute__((packed)) {
  u8 peer_id_addr_type;
  u8 peer_id_addr[6];
  u8 priv_mode;
} bt_hci_cmd_le_set_priv_mode;

#define BT_HCI_CMD_LE_RECEIVER_TEST_V3 0x204f
typedef struct __attribute__((packed)) {
  u8 rx_chan;
  u8 phy;
  u8 mod_index;
  u8 cte_len;
  u8 cte_type;
  u8 duration;
  u8 num_antenna_id;
  u8 antenna_ids[0];
} bt_hci_cmd_le_receiver_test_v3;

#define BT_HCI_CMD_LE_TX_TEST_V3 0x2050
typedef struct __attribute__((packed)) {
  u8 chan;
  u8 data_len;
  u8 payload;
  u8 phy;
  u8 cte_len;
  u8 cte_type;
  u8 duration;
  u8 num_antenna_id;
  u8 antenna_ids[0];
} bt_hci_cmd_le_tx_test_v3;

#define BT_HCI_CMD_SET_PA_REC_ENABLE 0x2059
typedef struct __attribute__((packed)) {
  u16 sync_handle;
  u8 enable;
} bt_hci_cmd_set_pa_rec_enable;

#define BT_HCI_CMD_PERIODIC_SYNC_TRANS 0x205a
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 service_data;
  u16 sync_handle;
} bt_hci_cmd_periodic_sync_trans;

#define BT_HCI_CMD_PA_SET_INFO_TRANS 0x205b
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 service_data;
  u16 adv_handle;
} bt_hci_cmd_pa_set_info_trans;

#define BT_HCI_CMD_PA_SYNC_TRANS_PARAMS 0x205c
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 mode;
  u16 skip;
  u16 sync_timeout;
  u8 cte_type;
} bt_hci_cmd_pa_sync_trans_params;

#define BT_HCI_CMD_DEFAULT_PA_SYNC_TRANS_PARAMS 0x205d
typedef struct __attribute__((packed)) {
  u8 mode;
  u16 skip;
  u16 sync_timeout;
  u8 cte_type;
} bt_hci_cmd_default_pa_sync_trans_params;

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE_V2 0x2060
#define BT_HCI_BIT_LE_READ_BUFFER_SIZE_V2 BT_HCI_CMD_BIT(41, 5)
typedef struct __attribute__((packed)) {
  u8 status;
  u16 acl_mtu;
  u8 acl_max_pkt;
  u16 iso_mtu;
  u8 iso_max_pkt;
} bt_hci_rsp_le_read_buffer_size_v2;

#define BT_HCI_CMD_LE_READ_ISO_TX_SYNC 0x2061
#define BT_HCI_BIT_LE_READ_ISO_TX_SYNC BT_HCI_CMD_BIT(41, 6)
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_read_iso_tx_sync;

typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 seq;
  u32 timestamp;
  u8 offset[3];
} bt_hci_rsp_le_read_iso_tx_sync;

#define BT_HCI_CMD_LE_SET_CIG_PARAMS 0x2062
#define BT_HCI_BIT_LE_SET_CIG_PARAMS BT_HCI_CMD_BIT(41, 7)
typedef struct __attribute__((packed)) {
  u8 cis_id;
  u16 c_sdu;
  u16 p_sdu;
  u8 c_phy;
  u8 p_phy;
  u8 c_rtn;
  u8 p_rtn;
} bt_hci_cis_params;

typedef struct __attribute__((packed)) {
  u8 cig_id;
  u8 c_interval[3];
  u8 p_interval[3];
  u8 sca;
  u8 packing;
  u8 framing;
  u16 c_latency;
  u16 p_latency;
  u8 num_cis;
  bt_hci_cis_params cis[0];
} bt_hci_cmd_le_set_cig_params;

typedef struct __attribute__((packed)) {
  u8 status;
  u8 cig_id;
  u8 num_handles;
  u16 handle[0];
} bt_hci_rsp_le_set_cig_params;

#define BT_HCI_CMD_LE_SET_CIG_PARAMS_TEST 0x2063
#define BT_HCI_BIT_LE_SET_CIG_PARAMS_TEST BT_HCI_CMD_BIT(42, 0)
typedef struct __attribute__((packed)) {
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
} bt_hci_cis_params_test;

typedef struct __attribute__((packed)) {
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
  bt_hci_cis_params_test cis[0];
} bt_hci_cmd_le_set_cig_params_test;

#define BT_HCI_CMD_LE_CREATE_CIS 0x2064
#define BT_HCI_BIT_LE_CREATE_CIS BT_HCI_CMD_BIT(42, 1)
typedef struct __attribute__((packed)) {
  u16 cis_handle;
  u16 acl_handle;
} bt_hci_cis;

typedef struct __attribute__((packed)) {
  u8 num_cis;
  bt_hci_cis cis[0];
} bt_hci_cmd_le_create_cis;

#define BT_HCI_CMD_LE_REMOVE_CIG 0x2065
#define BT_HCI_BIT_LE_REMOVE_CIG BT_HCI_CMD_BIT(42, 2)
typedef struct __attribute__((packed)) {
  u8 cig_id;
} bt_hci_cmd_le_remove_cig;

typedef struct __attribute__((packed)) {
  u8 status;
  u8 cig_id;
} bt_hci_rsp_le_remove_cig;

#define BT_HCI_CMD_LE_ACCEPT_CIS 0x2066
#define BT_HCI_BIT_LE_ACCEPT_CIS BT_HCI_CMD_BIT(42, 3)
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_accept_cis;

#define BT_HCI_CMD_LE_REJECT_CIS 0x2067
#define BT_HCI_BIT_LE_REJECT_CIS BT_HCI_CMD_BIT(42, 4)
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 reason;
} bt_hci_cmd_le_reject_cis;

#define BT_HCI_CMD_LE_CREATE_BIG 0x2068
#define BT_HCI_BIT_LE_CREATE_BIG BT_HCI_CMD_BIT(42, 5)
typedef struct __attribute__((packed)) {
  u8 sdu_interval[3];
  u16 sdu;
  u16 latency;
  u8 rtn;
  u8 phy;
  u8 packing;
  u8 framing;
  u8 encryption;
  u8 bcode[16];
} bt_hci_bis;

typedef struct __attribute__((packed)) {
  u8 handle;
  u8 adv_handle;
  u8 num_bis;
  bt_hci_bis bis;
} bt_hci_cmd_le_create_big;

#define BT_HCI_CMD_LE_CREATE_BIG_TEST 0x2069
#define BT_HCI_BIT_LE_CREATE_BIG_TEST BT_HCI_CMD_BIT(42, 6)
typedef struct __attribute__((packed)) {
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
} bt_hci_bis_test;

typedef struct __attribute__((packed)) {
  u8 big_id;
  u8 adv_handle;
  u8 num_bis;
  bt_hci_bis_test bis[0];
} bt_hci_cmd_le_create_big_test;

#define BT_HCI_CMD_LE_TERM_BIG 0x206a
#define BT_HCI_BIT_LE_TERM_BIG BT_HCI_CMD_BIT(42, 7)
typedef struct __attribute__((packed)) {
  u8 handle;
  u8 reason;
} bt_hci_cmd_le_term_big;

#define BT_HCI_CMD_LE_BIG_CREATE_SYNC 0x206b
#define BT_HCI_BIT_LE_BIG_CREATE_SYNC BT_HCI_CMD_BIT(43, 0)
typedef struct __attribute__((packed)) {
  u8 index;
} bt_hci_bis_sync;

typedef struct __attribute__((packed)) {
  u8 handle;
  u16 sync_handle;
  u8 encryption;
  u8 bcode[16];
  u8 mse;
  u16 timeout;
  u8 num_bis;
  bt_hci_bis_sync bis[0];
} bt_hci_cmd_le_big_create_sync;

#define BT_HCI_CMD_LE_BIG_TERM_SYNC 0x206c
#define BT_HCI_BIT_LE_BIG_TERM_SYNC BT_HCI_CMD_BIT(43, 1)
typedef struct __attribute__((packed)) {
  u8 handle;
} bt_hci_cmd_le_big_term_sync;

typedef struct __attribute__((packed)) {
  u8 status;
  u8 handle;
} bt_hci_rsp_le_big_term_sync;

#define BT_HCI_CMD_LE_REQ_PEER_SCA 0x206d
#define BT_HCI_BIT_LE_REQ_PEER_SCA BT_HCI_CMD_BIT(43, 2)
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_cmd_le_req_peer_sca;

#define BT_HCI_CMD_LE_SETUP_ISO_PATH 0x206e
#define BT_HCI_BIT_LE_SETUP_ISO_PATH BT_HCI_CMD_BIT(43, 3)
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 direction;
  u8 path;
  u8 codec;
  u16 codec_cid;
  u16 codec_vid;
  u8 delay[3];
  u8 codec_cfg_len;
  u8 codec_cfg[0];
} bt_hci_cmd_le_setup_iso_path;

typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_rsp_le_setup_iso_path;

#define BT_HCI_CMD_LE_REMOVE_ISO_PATH 0x206f
#define BT_HCI_BIT_LE_REMOVE_ISO_PATH BT_HCI_CMD_BIT(43, 4)
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 direction;
} bt_hci_cmd_le_remove_iso_path;

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
typedef struct __attribute__((packed)) {
  u8 bit_number;
  u8 bit_value;
} bt_hci_cmd_le_set_host_feature;

#define BT_HCI_EVT_INQUIRY_COMPLETE 0x01
typedef struct __attribute__((packed)) {
  u8 status;
} bt_hci_evt_inquiry_complete;

#define BT_HCI_EVT_INQUIRY_RESULT 0x02
typedef struct __attribute__((packed)) {
  u8 num_resp;
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_period_mode;
  u8 pscan_mode;
  u8 dev_class[3];
  u16 clock_offset;
} bt_hci_evt_inquiry_result;

#define BT_HCI_EVT_CONN_COMPLETE 0x03
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 bdaddr[6];
  u8 link_type;
  u8 encr_mode;
} bt_hci_evt_conn_complete;

#define BT_HCI_EVT_CONN_REQUEST 0x04
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 dev_class[3];
  u8 link_type;
} bt_hci_evt_conn_request;

#define BT_HCI_EVT_DISCONNECT_COMPLETE 0x05
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 reason;
} bt_hci_evt_disconnect_complete;

#define BT_HCI_EVT_AUTH_COMPLETE 0x06
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_evt_auth_complete;

#define BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE 0x07
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
  u8 name[248];
} bt_hci_evt_remote_name_request_complete;

#define BT_HCI_EVT_ENCRYPT_CHANGE 0x08
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 encr_mode;
} bt_hci_evt_encrypt_change;

#define BT_HCI_EVT_CHANGE_CONN_LINK_KEY_COMPLETE 0x09
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_evt_change_conn_link_key_complete;

#define BT_HCI_EVT_LINK_KEY_TYPE_CHANGED 0x0a
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 key_flag;
} bt_hci_evt_link_key_type_changed;

#define BT_HCI_EVT_REMOTE_FEATURES_COMPLETE 0x0b
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 features[8];
} bt_hci_evt_remote_features_complete;

#define BT_HCI_EVT_REMOTE_VERSION_COMPLETE 0x0c
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 lmp_ver;
  u16 manufacturer;
  u16 lmp_subver;
} bt_hci_evt_remote_version_complete;

#define BT_HCI_EVT_QOS_SETUP_COMPLETE 0x0d
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 flags;
  u8 service_type;
  u32 token_rate;
  u32 peak_bandwidth;
  u32 latency;
  u32 delay_variation;
} bt_hci_evt_qos_setup_complete;

#define BT_HCI_EVT_CMD_COMPLETE 0x0e
typedef struct __attribute__((packed)) {
  u8 ncmd;
  u16 opcode;
  u8 param[0];
} bt_hci_evt_cmd_complete;

#define BT_HCI_EVT_CMD_STATUS 0x0f
typedef struct __attribute__((packed)) {
  u8 status;
  u8 ncmd;
  u16 opcode;
} bt_hci_evt_cmd_status;

#define BT_HCI_EVT_HARDWARE_ERROR 0x10
typedef struct __attribute__((packed)) {
  u8 code;
} bt_hci_evt_hardware_error;

#define BT_HCI_EVT_FLUSH_OCCURRED 0x11
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_evt_flush_occurred;

#define BT_HCI_EVT_ROLE_CHANGE 0x12
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
  u8 role;
} bt_hci_evt_role_change;

#define BT_HCI_EVT_NUM_COMPLETED_PACKETS 0x13
typedef struct __attribute__((packed)) {
  u8 num_handles;
  u16 handle;
  u16 count;
} bt_hci_evt_num_completed_packets;

#define BT_HCI_EVT_MODE_CHANGE 0x14
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 mode;
  u16 interval;
} bt_hci_evt_mode_change;

#define BT_HCI_EVT_RETURN_LINK_KEYS 0x15
typedef struct __attribute__((packed)) {
  u8 num_keys;
  u8 keys[0];
} bt_hci_evt_return_link_keys;

#define BT_HCI_EVT_PIN_CODE_REQUEST 0x16
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_evt_pin_code_request;

#define BT_HCI_EVT_LINK_KEY_REQUEST 0x17
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_evt_link_key_request;

#define BT_HCI_EVT_LINK_KEY_NOTIFY 0x18
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 link_key[16];
  u8 key_type;
} bt_hci_evt_link_key_notify;

#define BT_HCI_EVT_LOOPBACK_COMMAND 0x19

#define BT_HCI_EVT_DATA_BUFFER_OVERFLOW 0x1a
typedef struct __attribute__((packed)) {
  u8 link_type;
} bt_hci_evt_data_buffer_overflow;

#define BT_HCI_EVT_MAX_SLOTS_CHANGE 0x1b
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 max_slots;
} bt_hci_evt_max_slots_change;

#define BT_HCI_EVT_CLOCK_OFFSET_COMPLETE 0x1c
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 clock_offset;
} bt_hci_evt_clock_offset_complete;

#define BT_HCI_EVT_CONN_PKT_TYPE_CHANGED 0x1d
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 pkt_type;
} bt_hci_evt_conn_pkt_type_changed;

#define BT_HCI_EVT_QOS_VIOLATION 0x1e
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_evt_qos_violation;

#define BT_HCI_EVT_PSCAN_MODE_CHANGE 0x1f
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 pscan_mode;
} bt_hci_evt_pscan_mode_change;

#define BT_HCI_EVT_PSCAN_REP_MODE_CHANGE 0x20
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 pscan_rep_mode;
} bt_hci_evt_pscan_rep_mode_change;

#define BT_HCI_EVT_FLOW_SPEC_COMPLETE 0x21
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 flags;
  u8 direction;
  u8 service_type;
  u32 token_rate;
  u32 token_bucket_size;
  u32 peak_bandwidth;
  u32 access_latency;
} bt_hci_evt_flow_spec_complete;

#define BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI 0x22
typedef struct __attribute__((packed)) {
  u8 num_resp;
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_period_mode;
  u8 dev_class[3];
  u16 clock_offset;
  int8_t rssi;
} bt_hci_evt_inquiry_result_with_rssi;

#define BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE 0x23
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 page;
  u8 max_page;
  u8 features[8];
} bt_hci_evt_remote_ext_features_complete;

#define BT_HCI_EVT_SYNC_CONN_COMPLETE 0x2c
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 bdaddr[6];
  u8 link_type;
  u8 tx_interval;
  u8 retrans_window;
  u16 rx_pkt_len;
  u16 tx_pkt_len;
  u8 air_mode;
} bt_hci_evt_sync_conn_complete;

#define BT_HCI_EVT_SYNC_CONN_CHANGED 0x2d
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 tx_interval;
  u8 retrans_window;
  u16 rx_pkt_len;
  u16 tx_pkt_len;
} bt_hci_evt_sync_conn_changed;

#define BT_HCI_EVT_SNIFF_SUBRATING 0x2e
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 max_tx_latency;
  u16 max_rx_latency;
  u16 min_remote_timeout;
  u16 min_local_timeout;
} bt_hci_evt_sniff_subrating;

#define BT_HCI_EVT_EXT_INQUIRY_RESULT 0x2f
typedef struct __attribute__((packed)) {
  u8 num_resp;
  u8 bdaddr[6];
  u8 pscan_rep_mode;
  u8 pscan_period_mode;
  u8 dev_class[3];
  u16 clock_offset;
  int8_t rssi;
  u8 data[240];
} bt_hci_evt_ext_inquiry_result;

#define BT_HCI_EVT_ENCRYPT_KEY_REFRESH_COMPLETE 0x30
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_evt_encrypt_key_refresh_complete;

#define BT_HCI_EVT_IO_CAPABILITY_REQUEST 0x31
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_evt_io_capability_request;

#define BT_HCI_EVT_IO_CAPABILITY_RESPONSE 0x32
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 capability;
  u8 oob_data;
  u8 authentication;
} bt_hci_evt_io_capability_response;

#define BT_HCI_EVT_USER_CONFIRM_REQUEST 0x33
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u32 passkey;
} bt_hci_evt_user_confirm_request;

#define BT_HCI_EVT_USER_PASSKEY_REQUEST 0x34
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_evt_user_passkey_request;

#define BT_HCI_EVT_REMOTE_OOB_DATA_REQUEST 0x35
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
} bt_hci_evt_remote_oob_data_request;

#define BT_HCI_EVT_SIMPLE_PAIRING_COMPLETE 0x36
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_evt_simple_pairing_complete;

#define BT_HCI_EVT_LINK_SUPV_TIMEOUT_CHANGED 0x38
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 timeout;
} bt_hci_evt_link_supv_timeout_changed;

#define BT_HCI_EVT_ENHANCED_FLUSH_COMPLETE 0x39
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_evt_enhanced_flush_complete;

#define BT_HCI_EVT_USER_PASSKEY_NOTIFY 0x3b
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u32 passkey;
} bt_hci_evt_user_passkey_notify;

#define BT_HCI_EVT_KEYPRESS_NOTIFY 0x3c
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 type;
} bt_hci_evt_keypress_notify;

#define BT_HCI_EVT_REMOTE_HOST_FEATURES_NOTIFY 0x3d
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 features[8];
} bt_hci_evt_remote_host_features_notify;

#define BT_HCI_EVT_LE_META_EVENT 0x3e

#define BT_HCI_EVT_PHY_LINK_COMPLETE 0x40
typedef struct __attribute__((packed)) {
  u8 status;
  u8 phy_handle;
} bt_hci_evt_phy_link_complete;

#define BT_HCI_EVT_CHANNEL_SELECTED 0x41
typedef struct __attribute__((packed)) {
  u8 phy_handle;
} bt_hci_evt_channel_selected;

#define BT_HCI_EVT_DISCONN_PHY_LINK_COMPLETE 0x42
typedef struct __attribute__((packed)) {
  u8 status;
  u8 phy_handle;
  u8 reason;
} bt_hci_evt_disconn_phy_link_complete;

#define BT_HCI_EVT_PHY_LINK_LOSS_EARLY_WARNING 0x43
typedef struct __attribute__((packed)) {
  u8 phy_handle;
  u8 reason;
} bt_hci_evt_phy_link_loss_early_warning;

#define BT_HCI_EVT_PHY_LINK_RECOVERY 0x44
typedef struct __attribute__((packed)) {
  u8 phy_handle;
} bt_hci_evt_phy_link_recovery;

#define BT_HCI_EVT_LOGIC_LINK_COMPLETE 0x45
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 phy_handle;
  u8 flow_spec;
} bt_hci_evt_logic_link_complete;

#define BT_HCI_EVT_DISCONN_LOGIC_LINK_COMPLETE 0x46
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 reason;
} bt_hci_evt_disconn_logic_link_complete;

#define BT_HCI_EVT_FLOW_SPEC_MODIFY_COMPLETE 0x47
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_evt_flow_spec_modify_complete;

#define BT_HCI_EVT_NUM_COMPLETED_DATA_BLOCKS 0x48
typedef struct __attribute__((packed)) {
  u16 total_num_blocks;
  u8 num_handles;
  u16 handle;
  u16 num_packets;
  u16 num_blocks;
} bt_hci_evt_num_completed_data_blocks;

#define BT_HCI_EVT_SHORT_RANGE_MODE_CHANGE 0x4c
typedef struct __attribute__((packed)) {
  u8 status;
  u8 phy_handle;
  u8 mode;
} bt_hci_evt_short_range_mode_change;

#define BT_HCI_EVT_AMP_STATUS_CHANGE 0x4d
typedef struct __attribute__((packed)) {
  u8 status;
  u8 amp_status;
} bt_hci_evt_amp_status_change;

#define BT_HCI_EVT_TRIGGERED_CLOCK_CAPTURE 0x4e
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 type;
  u32 clock;
  u16 clock_offset;
} bt_hci_evt_triggered_clock_capture;

#define BT_HCI_EVT_SYNC_TRAIN_COMPLETE 0x4f
typedef struct __attribute__((packed)) {
  u8 status;
} bt_hci_evt_sync_train_complete;

#define BT_HCI_EVT_SYNC_TRAIN_RECEIVED 0x50
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
  u32 offset;
  u8 map[10];
  u8 lt_addr;
  u32 instant;
  u16 interval;
  u8 service_data;
} bt_hci_evt_sync_train_received;

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_RECEIVE 0x51
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 lt_addr;
  u32 clock;
  u32 offset;
  u8 status;
  u8 fragment;
  u8 length;
} bt_hci_evt_peripheral_broadcast_receive;

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_TIMEOUT 0x52
typedef struct __attribute__((packed)) {
  u8 bdaddr[6];
  u8 lt_addr;
} bt_hci_evt_peripheral_broadcast_timeout;

#define BT_HCI_EVT_TRUNCATED_PAGE_COMPLETE 0x53
typedef struct __attribute__((packed)) {
  u8 status;
  u8 bdaddr[6];
} bt_hci_evt_truncated_page_complete;

#define BT_HCI_EVT_PERIPHERAL_PAGE_RESPONSE_TIMEOUT 0x54

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE 0x55
typedef struct __attribute__((packed)) {
  u8 map[10];
} bt_hci_evt_channel_map_change;

#define BT_HCI_EVT_INQUIRY_RESPONSE_NOTIFY 0x56
typedef struct __attribute__((packed)) {
  u8 lap[3];
  int8_t rssi;
} bt_hci_evt_inquiry_response_notify;

#define BT_HCI_EVT_AUTH_PAYLOAD_TIMEOUT_EXPIRED 0x57
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_evt_auth_payload_timeout_expired;

#define BT_HCI_EVT_LE_CONN_COMPLETE 0x01
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 role;
  u8 peer_addr_type;
  u8 peer_addr[6];
  u16 interval;
  u16 latency;
  u16 supv_timeout;
  u8 clock_accuracy;
} bt_hci_evt_le_conn_complete;

#define BT_HCI_EVT_LE_ADV_REPORT 0x02
typedef struct __attribute__((packed)) {
  u8 num_reports;
  u8 event_type;
  u8 addr_type;
  u8 addr[6];
  u8 data_len;
  u8 data[0];
} bt_hci_evt_le_adv_report;

#define BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE 0x03
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u16 interval;
  u16 latency;
  u16 supv_timeout;
} bt_hci_evt_le_conn_update_complete;

#define BT_HCI_EVT_LE_REMOTE_FEATURES_COMPLETE 0x04
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 features[8];
} bt_hci_evt_le_remote_features_complete;

#define BT_HCI_EVT_LE_LONG_TERM_KEY_REQUEST 0x05
typedef struct __attribute__((packed)) {
  u16 handle;
  u64 rand;
  u16 ediv;
} bt_hci_evt_le_long_term_key_request;

#define BT_HCI_EVT_LE_CONN_PARAM_REQUEST 0x06
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 supv_timeout;
} bt_hci_evt_le_conn_param_request;

#define BT_HCI_EVT_LE_DATA_LENGTH_CHANGE 0x07
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 max_tx_len;
  u16 max_tx_time;
  u16 max_rx_len;
  u16 max_rx_time;
} bt_hci_evt_le_data_length_change;

#define BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE 0x08
typedef struct __attribute__((packed)) {
  u8 status;
  u8 local_pk256[64];
} bt_hci_evt_le_read_local_pk256_complete;

#define BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE 0x09
typedef struct __attribute__((packed)) {
  u8 status;
  u8 dhkey[32];
} bt_hci_evt_le_generate_dhkey_complete;

#define BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE 0x0a
typedef struct __attribute__((packed)) {
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
} bt_hci_evt_le_enhanced_conn_complete;

#define BT_HCI_EVT_LE_DIRECT_ADV_REPORT 0x0b
typedef struct __attribute__((packed)) {
  u8 num_reports;
  u8 event_type;
  u8 addr_type;
  u8 addr[6];
  u8 direct_addr_type;
  u8 direct_addr[6];
  int8_t rssi;
} bt_hci_evt_le_direct_adv_report;

#define BT_HCI_EVT_LE_PHY_UPDATE_COMPLETE 0x0c
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 tx_phy;
  u8 rx_phy;
} bt_hci_evt_le_phy_update_complete;

#define BT_HCI_EVT_LE_EXT_ADV_REPORT 0x0d
typedef struct __attribute__((packed)) {
  u8 num_reports;
} bt_hci_evt_le_ext_adv_report;
typedef struct __attribute__((packed)) {
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
} bt_hci_le_ext_adv_report;

#define BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED 0x0e
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 sid;
  u8 addr_type;
  u8 addr[6];
  u8 phy;
  u16 interval;
  u8 clock_accuracy;
} bt_hci_evt_le_per_sync_established;

#define BT_HCI_EVT_LE_PA_REPORT 0x0f
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 tx_power;
  int8_t rssi;
  u8 cte_type;
  u8 data_status;
  u8 data_len;
  u8 data[0];
} bt_hci_le_pa_report;

#define BT_HCI_EVT_LE_PA_SYNC_LOST 0x10
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_hci_evt_le_per_sync_lost;

#define BT_HCI_EVT_LE_ADV_SET_TERM 0x12
typedef struct __attribute__((packed)) {
  u8 status;
  u8 handle;
  u16 conn_handle;
  u8 num_evts;
} bt_hci_evt_le_adv_set_term;

#define BT_HCI_EVT_LE_SCAN_REQ_RECEIVED 0x13
typedef struct __attribute__((packed)) {
  u8 handle;
  u8 scanner_addr_type;
  u8 scanner_addr[6];
} bt_hci_evt_le_scan_req_received;

#define BT_HCI_EVT_LE_CHAN_SELECT_ALG 0x14
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 algorithm;
} bt_hci_evt_le_chan_select_alg;

#define BT_HCI_EVT_LE_CTE_REQUEST_FAILED 0x17
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
} bt_hci_evt_le_cte_request_failed;

#define BT_HCI_EVT_LE_PA_SYNC_TRANS_REC 0x18
typedef struct __attribute__((packed)) {
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
} bt_hci_evt_le_pa_sync_trans_rec;

#define BT_HCI_EVT_LE_CIS_ESTABLISHED 0x19
typedef struct __attribute__((packed)) {
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
} bt_hci_evt_le_cis_established;

#define BT_HCI_EVT_LE_CIS_REQ 0x1a
typedef struct __attribute__((packed)) {
  u16 acl_handle;
  u16 cis_handle;
  u8 cig_id;
  u8 cis_id;
} bt_hci_evt_le_cis_req;

#define BT_HCI_EVT_LE_BIG_COMPLETE 0x1b
typedef struct __attribute__((packed)) {
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
} bt_hci_evt_le_big_complete;

#define BT_HCI_EVT_LE_BIG_TERMINATE 0x1c
typedef struct __attribute__((packed)) {
  u8 reason;
  u8 handle;
} bt_hci_evt_le_big_terminate;

#define BT_HCI_EVT_LE_BIG_SYNC_ESTABILISHED 0x1d
typedef struct __attribute__((packed)) {
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
} bt_hci_evt_le_big_sync_estabilished;

#define BT_HCI_EVT_LE_BIG_SYNC_LOST 0x1e
typedef struct __attribute__((packed)) {
  u8 big_id;
  u8 reason;
} bt_hci_evt_le_big_sync_lost;

#define BT_HCI_EVT_LE_REQ_PEER_SCA_COMPLETE 0x1f
typedef struct __attribute__((packed)) {
  u8 status;
  u16 handle;
  u8 sca;
} bt_hci_evt_le_req_peer_sca_complete;

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

typedef struct __attribute__((packed)) {
  u16 len;
  u16 cid;
  u8 data[];
} bt_l2cap_hdr;

typedef struct __attribute__((packed)) {
  u8 code;
  u8 ident;
  u16 len;
} bt_l2cap_hdr_sig;

#define BT_L2CAP_PDU_CMD_REJECT 0x01
typedef struct __attribute__((packed)) {
  u16 reason;
} bt_l2cap_pdu_cmd_reject;

#define BT_L2CAP_PDU_CONN_REQ 0x02
typedef struct __attribute__((packed)) {
  u16 psm;
  u16 scid;
} bt_l2cap_pdu_conn_req;

#define BT_L2CAP_PDU_CONN_RSP 0x03
typedef struct __attribute__((packed)) {
  u16 dcid;
  u16 scid;
  u16 result;
  u16 status;
} bt_l2cap_pdu_conn_rsp;

#define BT_L2CAP_PDU_CONFIG_REQ 0x04
typedef struct __attribute__((packed)) {
  u16 dcid;
  u16 flags;
} bt_l2cap_pdu_config_req;

#define BT_L2CAP_PDU_CONFIG_RSP 0x05
typedef struct __attribute__((packed)) {
  u16 scid;
  u16 flags;
  u16 result;
} bt_l2cap_pdu_config_rsp;

#define BT_L2CAP_PDU_DISCONN_REQ 0x06
typedef struct __attribute__((packed)) {
  u16 dcid;
  u16 scid;
} bt_l2cap_pdu_disconn_req;

#define BT_L2CAP_PDU_DISCONN_RSP 0x07
typedef struct __attribute__((packed)) {
  u16 dcid;
  u16 scid;
} bt_l2cap_pdu_disconn_rsp;

#define BT_L2CAP_PDU_ECHO_REQ 0x08

#define BT_L2CAP_PDU_ECHO_RSP 0x09

#define BT_L2CAP_PDU_INFO_REQ 0x0a
typedef struct __attribute__((packed)) {
  u16 type;
} bt_l2cap_pdu_info_req;

#define BT_L2CAP_PDU_INFO_RSP 0x0b
typedef struct __attribute__((packed)) {
  u16 type;
  u16 result;
  u8 data[0];
} bt_l2cap_pdu_info_rsp;

#define BT_L2CAP_PDU_CREATE_CHAN_REQ 0x0c
typedef struct __attribute__((packed)) {
  u16 psm;
  u16 scid;
  u8 ctrlid;
} bt_l2cap_pdu_create_chan_req;

#define BT_L2CAP_PDU_CREATE_CHAN_RSP 0x0d
typedef struct __attribute__((packed)) {
  u16 dcid;
  u16 scid;
  u16 result;
  u16 status;
} bt_l2cap_pdu_create_chan_rsp;

#define BT_L2CAP_PDU_MOVE_CHAN_REQ 0x0e
typedef struct __attribute__((packed)) {
  u16 icid;
  u8 ctrlid;
} bt_l2cap_pdu_move_chan_req;

#define BT_L2CAP_PDU_MOVE_CHAN_RSP 0x0f
typedef struct __attribute__((packed)) {
  u16 icid;
  u16 result;
} bt_l2cap_pdu_move_chan_rsp;

#define BT_L2CAP_PDU_MOVE_CHAN_CFM 0x10
typedef struct __attribute__((packed)) {
  u16 icid;
  u16 result;
} bt_l2cap_pdu_move_chan_cfm;

#define BT_L2CAP_PDU_MOVE_CHAN_CFM_RSP 0x11
typedef struct __attribute__((packed)) {
  u16 icid;
} bt_l2cap_pdu_move_chan_cfm_rsp;

#define BT_L2CAP_PDU_CONN_PARAM_REQ 0x12
typedef struct __attribute__((packed)) {
  u16 min_interval;
  u16 max_interval;
  u16 latency;
  u16 timeout;
} bt_l2cap_pdu_conn_param_req;

#define BT_L2CAP_PDU_CONN_PARAM_RSP 0x13
typedef struct __attribute__((packed)) {
  u16 result;
} bt_l2cap_pdu_conn_param_rsp;

#define BT_L2CAP_PDU_LE_CONN_REQ 0x14
typedef struct __attribute__((packed)) {
  u16 psm;
  u16 scid;
  u16 mtu;
  u16 mps;
  u16 credits;
} bt_l2cap_pdu_le_conn_req;

#define BT_L2CAP_PDU_LE_CONN_RSP 0x15
typedef struct __attribute__((packed)) {
  u16 dcid;
  u16 mtu;
  u16 mps;
  u16 credits;
  u16 result;
} bt_l2cap_pdu_le_conn_rsp;

#define BT_L2CAP_PDU_LE_FLOWCTL_CREDS 0x16
typedef struct __attribute__((packed)) {
  u16 cid;
  u16 credits;
} bt_l2cap_pdu_le_flowctl_creds;

#define BT_L2CAP_PDU_ECRED_CONN_REQ 0x17
typedef struct __attribute__((packed)) {
  u16 psm;
  u16 mtu;
  u16 mps;
  u16 credits;
  u16 scid[0];
} bt_l2cap_pdu_ecred_conn_req;

#define BT_L2CAP_PDU_ECRED_CONN_RSP 0x18
typedef struct __attribute__((packed)) {
  u16 mtu;
  u16 mps;
  u16 credits;
  u16 result;
  u16 dcid[0];
} bt_l2cap_pdu_ecred_conn_rsp;

#define BT_L2CAP_PDU_ECRED_RECONF_REQ 0x19
typedef struct __attribute__((packed)) {
  u16 mtu;
  u16 mps;
  u16 scid[0];
} bt_l2cap_pdu_ecred_reconf_req;

#define BT_L2CAP_PDU_ECRED_RECONF_RSP 0x1a
typedef struct __attribute__((packed)) {
  u16 result;
} bt_l2cap_pdu_ecred_reconf_rsp;

typedef struct __attribute__((packed)) {
  u16 psm;
} bt_l2cap_hdr_connless;

typedef struct __attribute__((packed)) {
  u8 code;
  u8 ident;
  u16 len;
} bt_l2cap_hdr_amp;

#define BT_L2CAP_AMP_CMD_REJECT 0x01
typedef struct __attribute__((packed)) {
  u16 reason;
} bt_l2cap_amp_cmd_reject;

#define BT_L2CAP_AMP_DISCOVER_REQ 0x02
typedef struct __attribute__((packed)) {
  u16 size;
  u16 features;
} bt_l2cap_amp_discover_req;

#define BT_L2CAP_AMP_DISCOVER_RSP 0x03
typedef struct __attribute__((packed)) {
  u16 size;
  u16 features;
} bt_l2cap_amp_discover_rsp;

#define BT_L2CAP_AMP_CHANGE_NOTIFY 0x04

#define BT_L2CAP_AMP_CHANGE_RESPONSE 0x05

#define BT_L2CAP_AMP_GET_INFO_REQ 0x06
typedef struct __attribute__((packed)) {
  u8 ctrlid;
} bt_l2cap_amp_get_info_req;

#define BT_L2CAP_AMP_GET_INFO_RSP 0x07
typedef struct __attribute__((packed)) {
  u8 ctrlid;
  u8 status;
  u32 total_bw;
  u32 max_bw;
  u32 min_latency;
  u16 pal_cap;
  u16 max_assoc_len;
} bt_l2cap_amp_get_info_rsp;

#define BT_L2CAP_AMP_GET_ASSOC_REQ 0x08
typedef struct __attribute__((packed)) {
  u8 ctrlid;
} bt_l2cap_amp_get_assoc_req;

#define BT_L2CAP_AMP_GET_ASSOC_RSP 0x09
typedef struct __attribute__((packed)) {
  u8 ctrlid;
  u8 status;
} bt_l2cap_amp_get_assoc_rsp;

#define BT_L2CAP_AMP_CREATE_PHY_LINK_REQ 0x0a
typedef struct __attribute__((packed)) {
  u8 local_ctrlid;
  u8 remote_ctrlid;
} bt_l2cap_amp_create_phy_link_req;

#define BT_L2CAP_AMP_CREATE_PHY_LINK_RSP 0x0b
typedef struct __attribute__((packed)) {
  u8 local_ctrlid;
  u8 remote_ctrlid;
  u8 status;
} bt_l2cap_amp_create_phy_link_rsp;

#define BT_L2CAP_AMP_DISCONN_PHY_LINK_REQ 0x0c
typedef struct __attribute__((packed)) {
  u8 local_ctrlid;
  u8 remote_ctrlid;
} bt_l2cap_amp_disconn_phy_link_req;

#define BT_L2CAP_AMP_DISCONN_PHY_LINK_RSP 0x0d
typedef struct __attribute__((packed)) {
  u8 local_ctrlid;
  u8 remote_ctrlid;
  u8 status;
} bt_l2cap_amp_disconn_phy_link_rsp;

typedef struct __attribute__((packed)) {
  u8 code;
  u8 data[0];
} bt_l2cap_hdr_att;

#define BT_L2CAP_ATT_ERROR_RESPONSE 0x01
typedef struct __attribute__((packed)) {
  u8 request;
  u16 handle;
  u8 error;
} bt_l2cap_att_error_response;

#define BT_L2CAP_ATT_EXCHANGE_MTU_REQ 0x02
typedef struct __attribute__((packed)) {
  u16 mtu;
} bt_l2cap_att_exchange_mtu_req;

#define BT_L2CAP_ATT_EXCHANGE_MTU_RSP 0x03
typedef struct __attribute__((packed)) {
  u16 mtu;
} bt_l2cap_att_exchange_mtu_rsp;

#define BT_L2CAP_ATT_FIND_INFORMATION_REQ 0x04
typedef struct __attribute__((packed)) {
  u16 start_handle;
  u16 end_handle;
} bt_l2cap_att_find_information_req;

#define BT_L2CAP_ATT_FIND_INFORMATION_RSP 0x05
typedef struct __attribute__((packed)) {
  u8 format;
  u8 data[0];
} bt_l2cap_att_find_information_rsp;

#define BT_L2CAP_ATT_FIND_TYPE_VALUE_REQ 0x06
typedef struct __attribute__((packed)) {
  u16 start_handle;
  u16 end_handle;
  u16 type;
  u8 value[0];
} bt_l2cap_att_find_type_value_req;

#define BT_L2CAP_ATT_FIND_TYPE_VALUE_RSP 0x07
typedef struct __attribute__((packed)) {
  u8 list[0];
} bt_l2cap_att_find_type_value_rsp;

#define BT_L2CAP_ATT_READ_TYPE_REQ 0x08
typedef struct __attribute__((packed)) {
  u16 start_handle;
  u16 end_handle;
  u8 type[16];
} bt_l2cap_att_read_type_req;

#define BT_L2CAP_ATT_READ_TYPE_RSP 0x09
typedef struct __attribute__((packed)) {
  u8 length;
  u8 list[0];
} bt_l2cap_att_read_type_rsp;

#define BT_L2CAP_ATT_READ_REQ 0x0a
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_l2cap_att_read_req;

#define BT_L2CAP_ATT_READ_RSP 0x0b
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_read_rsp;

#define BT_L2CAP_ATT_READ_BLOB_REQ 0x0c
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 offset;
} bt_l2cap_att_read_blob_req;

#define BT_L2CAP_ATT_READ_BLOB_RSP 0x0d
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_read_blob_rsp;

#define BT_L2CAP_ATT_READ_MULTIPLE_REQ 0x0e
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_read_multiple_req;

#define BT_L2CAP_ATT_READ_MULTIPLE_RSP 0x0f
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_read_multiple_rsp;

#define BT_L2CAP_ATT_READ_GROUP_TYPE_REQ 0x10
typedef struct __attribute__((packed)) {
  u16 start_handle;
  u16 end_handle;
  u8 type[16];
} bt_l2cap_att_read_group_type_req;

#define BT_L2CAP_ATT_READ_GROUP_TYPE_RSP 0x11
typedef struct __attribute__((packed)) {
  u8 length;
  u8 data[0];
} bt_l2cap_att_read_group_type_rsp;

#define BT_L2CAP_ATT_READ_MULTIPLE_VARIABLE_REQ 0x20
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_read_multiple_variable_req;

#define BT_L2CAP_ATT_READ_MULTIPLE_VARIABLE_RSP 0x21
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_read_multiple_variable_rsp;

#define BT_L2CAP_ATT_WRITE_REQ 0x12
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 data[0];
} bt_l2cap_att_write_req;

#define BT_L2CAP_ATT_WRITE_RSP 0x13
typedef struct __attribute__((packed)) {
} bt_l2cap_att_write_rsp;

#define BT_L2CAP_ATT_WRITE_CMD 0x52
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 data[0];
} bt_l2cap_att_write_cmd;

#define BT_L2CAP_ATT_SIGNED_WRITE_CMD 0xd2
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 data[0];
} bt_l2cap_att_signed_write_cmd;

#define BT_L2CAP_ATT_PREPARE_WRITE_REQ 0x16
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 offset;
  u8 data[0];
} bt_l2cap_att_prepare_write_req;

#define BT_L2CAP_ATT_PREPARE_WRITE_RSP 0x17
typedef struct __attribute__((packed)) {
  u16 handle;
  u16 offset;
  u8 data[0];
} bt_l2cap_att_prepare_write_rsp;

#define BT_L2CAP_ATT_EXECUTE_WRITE_REQ 0x18
typedef struct __attribute__((packed)) {
  u8 flags;
} bt_l2cap_att_execute_write_req;

#define BT_L2CAP_ATT_EXECUTE_WRITE_RSP 0x19
typedef struct __attribute__((packed)) {
} bt_l2cap_att_execute_write_rsp;

#define BT_L2CAP_ATT_HANDLE_VALUE_NOTIFY 0x1b
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 data[0];
} bt_l2cap_att_handle_value_notify;

#define BT_L2CAP_ATT_HANDLE_VALUE_IND 0x1d
typedef struct __attribute__((packed)) {
  u16 handle;
} bt_l2cap_att_handle_value_ind;

#define BT_L2CAP_ATT_HANDLE_VALUE_CONF 0x1e
typedef struct __attribute__((packed)) {
} bt_l2cap_att_handle_value_conf;

#define BT_L2CAP_ATT_MULTIPLE_HANDLE_VALUE_NTF 0x23
typedef struct __attribute__((packed)) {
  u8 data[0];
} bt_l2cap_att_multiple_handle_value_ntf;

typedef struct __attribute__((packed)) {
  u8 code;
} bt_l2cap_hdr_smp;

#define BT_L2CAP_SMP_PAIRING_REQUEST 0x01
typedef struct __attribute__((packed)) {
  u8 io_capa;
  u8 oob_data;
  u8 auth_req;
  u8 max_key_size;
  u8 init_key_dist;
  u8 resp_key_dist;
} bt_l2cap_smp_pairing_request;

#define BT_L2CAP_SMP_PAIRING_RESPONSE 0x02
typedef struct __attribute__((packed)) {
  u8 io_capa;
  u8 oob_data;
  u8 auth_req;
  u8 max_key_size;
  u8 init_key_dist;
  u8 resp_key_dist;
} bt_l2cap_smp_pairing_response;

#define BT_L2CAP_SMP_PAIRING_CONFIRM 0x03
typedef struct __attribute__((packed)) {
  u8 value[16];
} bt_l2cap_smp_pairing_confirm;

#define BT_L2CAP_SMP_PAIRING_RANDOM 0x04
typedef struct __attribute__((packed)) {
  u8 value[16];
} bt_l2cap_smp_pairing_random;

#define BT_L2CAP_SMP_PAIRING_FAILED 0x05
typedef struct __attribute__((packed)) {
  u8 reason;
} bt_l2cap_smp_pairing_failed;

#define BT_L2CAP_SMP_ENCRYPT_INFO 0x06
typedef struct __attribute__((packed)) {
  u8 ltk[16];
} bt_l2cap_smp_encrypt_info;

#define BT_L2CAP_SMP_CENTRAL_IDENT 0x07
typedef struct __attribute__((packed)) {
  u16 ediv;
  u64 rand;
} bt_l2cap_smp_central_ident;

#define BT_L2CAP_SMP_IDENT_INFO 0x08
typedef struct __attribute__((packed)) {
  u8 irk[16];
} bt_l2cap_smp_ident_info;

#define BT_L2CAP_SMP_IDENT_ADDR_INFO 0x09
typedef struct __attribute__((packed)) {
  u8 addr_type;
  u8 addr[6];
} bt_l2cap_smp_ident_addr_info;

#define BT_L2CAP_SMP_SIGNING_INFO 0x0a
typedef struct __attribute__((packed)) {
  u8 csrk[16];
} bt_l2cap_smp_signing_info;

#define BT_L2CAP_SMP_SECURITY_REQUEST 0x0b
typedef struct __attribute__((packed)) {
  u8 auth_req;
} bt_l2cap_smp_security_request;

#define BT_L2CAP_SMP_PUBLIC_KEY 0x0c
typedef struct __attribute__((packed)) {
  u8 x[32];
  u8 y[32];
} bt_l2cap_smp_public_key;

#define BT_L2CAP_SMP_DHKEY_CHECK 0x0d
typedef struct __attribute__((packed)) {
  u8 e[16];
} bt_l2cap_smp_dhkey_check;

#define BT_L2CAP_SMP_KEYPRESS_NOTIFY 0x0e
typedef struct __attribute__((packed)) {
  u8 type;
} bt_l2cap_smp_keypress_notify;

typedef struct __attribute__((packed)) {
  u8 pdu;
  u16 tid;
  u16 plen;
} bt_sdp_hdr;

typedef struct __attribute__((packed)) {
  u8 opcode;
  u8 param[];
} bt_l2cap_att_hdr;

// MARK: Attribute PDU Opcodes
#define ATT_ERROR_RESPONSE 0x01u

#define ATT_EXCHANGE_MTU_REQUEST 0x02u
typedef struct __attribute__((packed)) {
  u16 mtu;
}att_exchange_mtu_request;

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
typedef struct __attribute__((packed)) {
  u16 handle;
  u8 data[];
}att_write_request;


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
