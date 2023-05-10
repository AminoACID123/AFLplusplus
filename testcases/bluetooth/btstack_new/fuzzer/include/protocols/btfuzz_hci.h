#ifndef BTFUZZ_HCI_H
#define BTFUZZ_HCI_H

#include "common/type.h"
#include "common/util.h"
#include "btfuzz_state.h"


#define btfuzz_alloc_event(evt, code, param_size) \
	cast_define(bt_hci_evt_hdr*, evt, btfuzz->evt_buf); \
	evt->opcode = code; \
	evt->len = param_size;

#define btfuzz_alloc_le_event(evt, code, param_size) \
	cast_define(bt_hci_evt_hdr*, evt, btfuzz->evt_buf); \
	evt->opcode = BT_HCI_EVT_LE_META_EVENT; \
	evt->len = param_size + 1; \
	evt->param[0] = code;

typedef struct {
    u16 handle;
    btfuzz_vector_t pending_acl_buf;
}hci_connection_t;

void send_command_complete_event(u16 opcode, u8 ncmd, void *data, u32 len);

void send_command_status_event(u16 opcode, u8 ncmd, u8 status);

void send_connection_request_event(bd_addr_t addr);

void send_le_connection_complete_event(bd_addr_t addr, bd_addr_type_t type);

void create_le_connection(bd_addr_t addr, bd_addr_type_t type);

void hci_command_handler(u8 *packet, u32 len);

void hci_acl_handler(u8 *packet, u32 len);


/*
typedef struct {
    // linked list - assert: first field
    btfuzz_linked_item_t    item;
    
    // remote side
    bd_addr_t address;
    
    // module handle
    hci_con_handle_t con_handle;

    // le public, le random, classic
    bd_addr_type_t address_type;

    // role: 0 - master, 1 - slave
    uint8_t role;

    // connection state
    CONNECTION_STATE state;
    
    // bonding
    u32 bonding_flags;
    u8  bonding_status;

    // encryption key size (in octets)
    uint8_t encryption_key_size;

    // requested security level
    gap_security_level_t requested_security_level;
    
    // link key and its type
    link_key_t      link_key;
    link_key_type_t link_key_type;

    // remote supported features
    // bit 0 - eSCO 
    // bit 1 - extended features 
    uint8_t remote_supported_features[1];

#ifdef ENABLE_CLASSIC
    // IO Capabilities Response
    uint8_t io_cap_response_auth_req;
    uint8_t io_cap_response_io;
#ifdef ENABLE_CLASSIC_PAIRING_OOB
    uint8_t io_cap_response_oob_data;
#endif

    // connection mode, default ACL_CONNECTION_MODE_ACTIVE
    uint8_t connection_mode;

    // enter/exit sniff mode requests
    uint16_t sniff_min_interval;    // 0: idle, 0xffff exit sniff, else enter sniff
    uint16_t sniff_max_interval;
    uint16_t sniff_attempt;
    uint16_t sniff_timeout;

    // sniff subrating
    uint16_t sniff_subrating_max_latency;   // 0xffff = not set
    uint16_t sniff_subrating_min_remote_timeout;
    uint16_t sniff_subrating_min_local_timeout;

    // QoS
    hci_service_type_t qos_service_type;
    uint32_t qos_token_rate;
    uint32_t qos_peak_bandwidth;
    uint32_t qos_latency;
    uint32_t qos_delay_variation;

#ifdef ENABLE_SCO_OVER_HCI
    // track SCO rx event
    uint32_t sco_rx_ms;
    uint8_t  sco_rx_count;
    uint8_t  sco_rx_valid;
#endif
    // generate sco can send now based on received packets, using timeout below
    uint8_t  sco_tx_ready;

    // request role switch
    hci_role_t request_role;

    btfuzz_timer_source_t timeout_sco;
#endif 

    // authentication and other errands
    uint16_t authentication_flags;

    // gap connection tasks, see GAP_CONNECTION_TASK_x
    uint16_t gap_connection_tasks;

    btfuzz_timer_source_t timeout;

    // timeout in system ticks (HAVE_EMBEDDED_TICK) or milliseconds (HAVE_EMBEDDED_TIME_MS)
    uint32_t timestamp;

    // ACL packet recombination - PRE_BUFFER + ACL Header + ACL payload
    uint8_t  acl_recombination_buffer[HCI_INCOMING_PRE_BUFFER_SIZE + 4 + HCI_ACL_BUFFER_SIZE];
    uint16_t acl_recombination_pos;
    uint16_t acl_recombination_length;
    

    // number packets sent to controller
    uint8_t num_packets_sent;

#ifdef ENABLE_HCI_CONTROLLER_TO_HOST_FLOW_CONTROL
    uint8_t num_packets_completed;
#endif

    // LE Connection parameter update
    le_con_parameter_update_state_t le_con_parameter_update_state;
    uint8_t  le_con_param_update_identifier;
    uint16_t le_conn_interval_min;
    uint16_t le_conn_interval_max;
    uint16_t le_conn_latency;
    uint16_t le_supervision_timeout;

#ifdef ENABLE_BLE
    uint16_t le_connection_interval;

    // LE PHY Update via set phy command
    uint8_t le_phy_update_all_phys;      // 0xff for idle
    uint8_t le_phy_update_tx_phys;
    uint8_t le_phy_update_rx_phys;
    int8_t  le_phy_update_phy_options;

    // LE Security Manager
    sm_connection_t sm_connection;

#ifdef ENABLE_LE_LIMIT_ACL_FRAGMENT_BY_MAX_OCTETS
    uint16_t le_max_tx_octets;
#endif

    // ATT Connection
    att_connection_t att_connection;

    // ATT Server
    att_server_t    att_server;

#ifdef ENABLE_LE_PERIODIC_ADVERTISING
    hci_con_handle_t le_past_sync_handle;
    uint16_t         le_past_service_data;
#endif

#endif

    l2cap_state_t l2cap_state;

#ifdef ENABLE_CLASSIC_PAIRING_OOB
    const uint8_t * classic_oob_c_192;
    const uint8_t * classic_oob_r_192;
    const uint8_t * classic_oob_c_256;
    const uint8_t * classic_oob_r_256;
#endif

} hci_connection_t;

*/
#endif