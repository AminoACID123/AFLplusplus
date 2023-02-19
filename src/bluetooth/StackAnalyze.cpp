#include "Hci.h"
#include <bits/unique_ptr.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <set>
#include <vector>


#define BTSTACK "btstack"
#define NIMBLE "nimble"

using namespace llvm;
using namespace std;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define BT_HCI_EVT_LE_META_EVENT 0x3e

set<u8> sEvt;
set<u8> sLeEvt;

set<u16> sStatusCmd = {
    BT_HCI_CMD_INQUIRY,
    BT_HCI_CMD_CREATE_CONN,
    BT_HCI_CMD_DISCONNECT,
    BT_HCI_CMD_ACCEPT_CONN_REQUEST,
    BT_HCI_CMD_REJECT_CONN_REQUEST,
    BT_HCI_CMD_CHANGE_CONN_PKT_TYPE,
    BT_HCI_CMD_AUTH_REQUESTED,
    BT_HCI_CMD_SET_CONN_ENCRYPT,
    BT_HCI_CMD_CHANGE_CONN_LINK_KEY,
    BT_HCI_CMD_LINK_KEY_SELECTION,
    BT_HCI_CMD_REMOTE_NAME_REQUEST,
    BT_HCI_CMD_READ_REMOTE_FEATURES,
    BT_HCI_CMD_READ_REMOTE_EXT_FEATURES,
    BT_HCI_CMD_READ_REMOTE_VERSION,
    BT_HCI_CMD_READ_CLOCK_OFFSET,
    BT_HCI_CMD_SETUP_SYNC_CONN,
    BT_HCI_CMD_ACCEPT_SYNC_CONN_REQUEST,
    BT_HCI_CMD_REJECT_SYNC_CONN_REQUEST,
    BT_HCI_CMD_CREATE_PHY_LINK,
    BT_HCI_CMD_ACCEPT_PHY_LINK,
    BT_HCI_CMD_DISCONN_PHY_LINK,
    BT_HCI_CMD_CREATE_LOGIC_LINK,
    BT_HCI_CMD_ACCEPT_LOGIC_LINK,
    BT_HCI_CMD_DISCONN_LOGIC_LINK,
    BT_HCI_CMD_FLOW_SPEC_MODIFY,
    BT_HCI_CMD_ENHANCED_SETUP_SYNC_CONN,
    BT_HCI_CMD_ENHANCED_ACCEPT_SYNC_CONN_REQUEST,
    BT_HCI_CMD_TRUNCATED_PAGE,
    BT_HCI_CMD_START_SYNC_TRAIN,
    BT_HCI_CMD_RECEIVE_SYNC_TRAIN,
    BT_HCI_CMD_HOLD_MODE,
    BT_HCI_CMD_SNIFF_MODE,
    BT_HCI_CMD_EXIT_SNIFF_MODE,
    BT_HCI_CMD_QOS_SETUP,
    BT_HCI_CMD_SWITCH_ROLE,
    BT_HCI_CMD_FLOW_SPEC,
    BT_HCI_CMD_REFRESH_ENCRYPT_KEY,
    BT_HCI_CMD_ENHANCED_FLUSH,
    BT_HCI_CMD_SHORT_RANGE_MODE,
};
set<u16> sCompleteCmd = {
    BT_HCI_CMD_INQUIRY_CANCEL,
    BT_HCI_CMD_PERIODIC_INQUIRY,
    BT_HCI_CMD_EXIT_PERIODIC_INQUIRY,
    BT_HCI_CMD_CREATE_CONN_CANCEL,
    BT_HCI_CMD_LINK_KEY_REQUEST_REPLY,
    BT_HCI_CMD_LINK_KEY_REQUEST_NEG_REPLY,
    BT_HCI_CMD_PIN_CODE_REQUEST_REPLY,
    BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY,
    BT_HCI_CMD_REMOTE_NAME_REQUEST,
    BT_HCI_CMD_READ_LMP_HANDLE,
    BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY,
    BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
    BT_HCI_CMD_USER_CONFIRM_REQUEST_NEG_REPLY,
    BT_HCI_CMD_USER_PASSKEY_REQUEST_REPLY,
    BT_HCI_CMD_USER_PASSKEY_REQUEST_NEG_REPLY,
    BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_REPLY,
    BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_NEG_REPLY,
    BT_HCI_CMD_IO_CAPABILITY_REQUEST_NEG_REPLY,
    BT_HCI_CMD_LOGIC_LINK_CANCEL,
    BT_HCI_CMD_TRUNCATED_PAGE_CANCEL,
    BT_HCI_CMD_SET_PERIPHERAL_BROADCAST,
    BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_RECEIVE,
    BT_HCI_CMD_REMOTE_OOB_EXT_DATA_REQUEST_REPLY,
    BT_HCI_CMD_ROLE_DISCOVERY,
    BT_HCI_CMD_READ_LINK_POLICY,
    BT_HCI_CMD_WRITE_LINK_POLICY,
    BT_HCI_CMD_READ_DEFAULT_LINK_POLICY,
    BT_HCI_CMD_WRITE_DEFAULT_LINK_POLICY,
    BT_HCI_CMD_SNIFF_SUBRATING,
    BT_HCI_CMD_SET_EVENT_MASK,
    BT_HCI_CMD_RESET,
    BT_HCI_CMD_SET_EVENT_FILTER,
    BT_HCI_CMD_FLUSH,
    BT_HCI_CMD_READ_PIN_TYPE,
    BT_HCI_CMD_WRITE_PIN_TYPE,
    BT_HCI_CMD_READ_STORED_LINK_KEY,
    BT_HCI_CMD_WRITE_STORED_LINK_KEY,
    BT_HCI_CMD_DELETE_STORED_LINK_KEY,
    BT_HCI_CMD_WRITE_LOCAL_NAME,
    BT_HCI_CMD_READ_LOCAL_NAME,
    BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT,
    BT_HCI_CMD_WRITE_CONN_ACCEPT_TIMEOUT,
    BT_HCI_CMD_READ_PAGE_TIMEOUT,
    BT_HCI_CMD_WRITE_PAGE_TIMEOUT,
    BT_HCI_CMD_READ_SCAN_ENABLE,
    BT_HCI_CMD_WRITE_SCAN_ENABLE,
    BT_HCI_CMD_READ_PAGE_SCAN_ACTIVITY,
    BT_HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY,
    BT_HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY,
    BT_HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY,
    BT_HCI_CMD_READ_AUTH_ENABLE,
    BT_HCI_CMD_WRITE_AUTH_ENABLE,
    BT_HCI_CMD_READ_CLASS_OF_DEV,
    BT_HCI_CMD_WRITE_CLASS_OF_DEV,
    BT_HCI_CMD_READ_VOICE_SETTING,
    BT_HCI_CMD_WRITE_VOICE_SETTING,
    BT_HCI_CMD_READ_AUTO_FLUSH_TIMEOUT,
    BT_HCI_CMD_WRITE_AUTO_FLUSH_TIMEOUT,
    BT_HCI_CMD_READ_NUM_BROADCAST_RETRANS,
    BT_HCI_CMD_WRITE_NUM_BROADCAST_RETRANS,
    BT_HCI_CMD_READ_HOLD_MODE_ACTIVITY,
    BT_HCI_CMD_WRITE_HOLD_MODE_ACTIVITY,
    BT_HCI_CMD_READ_TX_POWER,
    BT_HCI_CMD_READ_SYNC_FLOW_CONTROL,
    BT_HCI_CMD_WRITE_SYNC_FLOW_CONTROL,
    BT_HCI_CMD_SET_HOST_FLOW_CONTROL,
    BT_HCI_CMD_HOST_BUFFER_SIZE,
    BT_HCI_CMD_READ_LINK_SUPV_TIMEOUT,
    BT_HCI_CMD_WRITE_LINK_SUPV_TIMEOUT,
    BT_HCI_CMD_READ_NUM_SUPPORTED_IAC,
    BT_HCI_CMD_READ_CURRENT_IAC_LAP,
    BT_HCI_CMD_WRITE_CURRENT_IAC_LAP,
    BT_HCI_CMD_SET_AFH_HOST_CLASSIFICATION,
    BT_HCI_CMD_READ_INQUIRY_SCAN_TYPE,
    BT_HCI_CMD_WRITE_INQUIRY_SCAN_TYPE,
    BT_HCI_CMD_READ_INQUIRY_MODE,
    BT_HCI_CMD_WRITE_INQUIRY_MODE,
    BT_HCI_CMD_READ_PAGE_SCAN_TYPE,
    BT_HCI_CMD_WRITE_PAGE_SCAN_TYPE,
    BT_HCI_CMD_READ_AFH_CHANNEL_MAP,
    BT_HCI_CMD_WRITE_AFH_ASSESSMENT_MODE,
    BT_HCI_CMD_READ_EXT_INQUIRY_RESPONSE,
    BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
    BT_HCI_CMD_READ_SIMPLE_PAIRING_MODE,
    BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE,
    BT_HCI_CMD_READ_LOCAL_OOB_DATA,
    BT_HCI_CMD_READ_INQUIRY_RESP_TX_POWER,
    BT_HCI_CMD_WRITE_INQUIRY_TX_POWER,
    BT_HCI_CMD_SEND_KEYPRESS_NOTIFY,
    BT_HCI_CMD_READ_ERRONEOUS_REPORTING,
    BT_HCI_CMD_WRITE_ERRONEOUS_REPORTING,
    BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT,
    BT_HCI_CMD_SET_EVENT_MASK_PAGE2,
    BT_HCI_CMD_READ_LOCATION_DATA,
    BT_HCI_CMD_WRITE_LOCATION_DATA,
    BT_HCI_CMD_READ_FLOW_CONTROL_MODE,
    BT_HCI_CMD_WRITE_FLOW_CONTROL_MODE,
    BT_HCI_CMD_READ_ENHANCED_TX_POWER,
    BT_HCI_CMD_READ_LE_HOST_SUPPORTED,
    BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED,
    BT_HCI_CMD_SET_RESERVED_LT_ADDR,
    BT_HCI_CMD_DELETE_RESERVED_LT_ADDR,
    BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_DATA,
    BT_HCI_CMD_READ_SYNC_TRAIN_PARAMS,
    BT_HCI_CMD_WRITE_SYNC_TRAIN_PARAMS,
    BT_HCI_CMD_READ_SECURE_CONN_SUPPORT,
    BT_HCI_CMD_WRITE_SECURE_CONN_SUPPORT,
    BT_HCI_CMD_READ_AUTH_PAYLOAD_TIMEOUT,
    BT_HCI_CMD_WRITE_AUTH_PAYLOAD_TIMEOUT,
    BT_HCI_CMD_READ_LOCAL_OOB_EXT_DATA,
    BT_HCI_CMD_READ_EXT_PAGE_TIMEOUT,
    BT_HCI_CMD_WRITE_EXT_PAGE_TIMEOUT,
    BT_HCI_CMD_READ_EXT_INQUIRY_LENGTH,
    BT_HCI_CMD_WRITE_EXT_INQUIRY_LENGTH,
    BT_HCI_CMD_CONFIG_DATA_PATH,
    BT_HCI_CMD_READ_LOCAL_VERSION,
    BT_HCI_CMD_READ_LOCAL_COMMANDS,
    BT_HCI_CMD_READ_LOCAL_FEATURES,
    BT_HCI_CMD_READ_LOCAL_EXT_FEATURES,
    BT_HCI_CMD_READ_BUFFER_SIZE,
    BT_HCI_CMD_READ_BD_ADDR,
    BT_HCI_CMD_READ_DATA_BLOCK_SIZE,
    BT_HCI_CMD_READ_LOCAL_CODECS,
    BT_HCI_CMD_READ_LOCAL_PAIRING_OPTIONS,
    BT_HCI_CMD_READ_LOCAL_CODEC_CAPS,
    BT_HCI_CMD_READ_LOCAL_CTRL_DELAY,
    BT_HCI_CMD_READ_FAILED_CONTACT_COUNTER,
    BT_HCI_CMD_RESET_FAILED_CONTACT_COUNTER,
    BT_HCI_CMD_READ_LINK_QUALITY,
    BT_HCI_CMD_READ_RSSI,
    BT_HCI_CMD_READ_AFH_CHANNEL_MAP,
    BT_HCI_CMD_READ_CLOCK,
    BT_HCI_CMD_READ_ENCRYPT_KEY_SIZE,
    BT_HCI_CMD_READ_LOCAL_AMP_INFO,
    BT_HCI_CMD_READ_LOCAL_AMP_ASSOC,
    BT_HCI_CMD_WRITE_REMOTE_AMP_ASSOC,
    BT_HCI_CMD_GET_MWS_TRANSPORT_CONFIG,
    BT_HCI_CMD_SET_TRIGGERED_CLOCK_CAPTURE,
    BT_HCI_CMD_READ_LOOPBACK_MODE,
    BT_HCI_CMD_WRITE_LOOPBACK_MODE,
    BT_HCI_CMD_ENABLE_DUT_MODE,
    BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE
};

BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS;
vector<u8> vEvt;
vector<u8> vLeEvt;


set<u8> hci_evts = {
    0x01, /*BT_HCI_EVT_INQUIRY_COMPLETE*/
    0x02, /*BT_HCI_EVT_INQUIRY_RESULT*/
    0x03, /*BT_HCI_EVT_CONN_COMPLETE*/
    0x04, /*BT_HCI_EVT_CONN_REQUEST*/
    0x05, /*BT_HCI_EVT_DISCONNECT_COMPLETE*/
    0x06, /*BT_HCI_EVT_AUTH_COMPLETE*/
    0x07, /*BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE*/
    0x08, /*BT_HCI_EVT_ENCRYPT_CHANGE*/
    0x09, /*BT_HCI_EVT_CHANGE_CONN_LINK_KEY_COMPLETE*/
    0x0a, /*BT_HCI_EVT_LINK_KEY_TYPE_CHANGED*/
    0x0b, /*BT_HCI_EVT_REMOTE_FEATURES_COMPLETE*/
    0x0c, /*BT_HCI_EVT_REMOTE_VERSION_COMPLETE*/
    0x0d, /*BT_HCI_EVT_QOS_SETUP_COMPLETE*/
    0x0e, /*BT_HCI_EVT_CMD_COMPLETE*/
    0x0f, /*BT_HCI_EVT_CMD_STATUS*/
    0x10, /*BT_HCI_EVT_HARDWARE_ERROR*/
    0x11, /*BT_HCI_EVT_FLUSH_OCCURRED*/
    0x12, /*BT_HCI_EVT_ROLE_CHANGE*/
    0x13, /*BT_HCI_EVT_NUM_COMPLETED_PACKETS*/
    0x14, /*BT_HCI_EVT_MODE_CHANGE*/
    0x15, /*BT_HCI_EVT_RETURN_LINK_KEYS*/
    0x16, /*BT_HCI_EVT_PIN_CODE_REQUEST*/
    0x17, /*BT_HCI_EVT_LINK_KEY_REQUEST*/
    0x18, /*BT_HCI_EVT_LINK_KEY_NOTIFY*/
    0x19, /*BT_HCI_EVT_LOOPBACK_COMMAND*/
    0x1a, /*BT_HCI_EVT_DATA_BUFFER_OVERFLOW*/
    0x1b, /*BT_HCI_EVT_MAX_SLOTS_CHANGE*/
    0x1c, /*BT_HCI_EVT_CLOCK_OFFSET_COMPLETE*/
    0x1d, /*BT_HCI_EVT_CONN_PKT_TYPE_CHANGED*/
    0x1e, /*BT_HCI_EVT_QOS_VIOLATION*/
    0x1f, /*BT_HCI_EVT_PSCAN_MODE_CHANGE*/
    0x20, /*BT_HCI_EVT_PSCAN_REP_MODE_CHANGE*/
    0x21, /*BT_HCI_EVT_FLOW_SPEC_COMPLETE*/
    0x22, /*BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI*/
    0x23, /*BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE*/
    0x2c, /*BT_HCI_EVT_SYNC_CONN_COMPLETE*/
    0x2d, /*BT_HCI_EVT_SYNC_CONN_CHANGED*/
    0x2e, /*BT_HCI_EVT_SNIFF_SUBRATING*/
    0x2f, /*BT_HCI_EVT_EXT_INQUIRY_RESULT*/
    0x30, /*BT_HCI_EVT_ENCRYPT_KEY_REFRESH_COMPLETE*/
    0x31, /*BT_HCI_EVT_IO_CAPABILITY_REQUEST*/
    0x32, /*BT_HCI_EVT_IO_CAPABILITY_RESPONSE*/
    0x33, /*BT_HCI_EVT_USER_CONFIRM_REQUEST*/
    0x34, /*BT_HCI_EVT_USER_PASSKEY_REQUEST*/
    0x35, /*BT_HCI_EVT_REMOTE_OOB_DATA_REQUEST*/
    0x36, /*BT_HCI_EVT_SIMPLE_PAIRING_COMPLETE*/
    0x38, /*BT_HCI_EVT_LINK_SUPV_TIMEOUT_CHANGED*/
    0x39, /*BT_HCI_EVT_ENHANCED_FLUSH_COMPLETE*/
    0x3b, /*BT_HCI_EVT_USER_PASSKEY_NOTIFY*/
    0x3c, /*BT_HCI_EVT_KEYPRESS_NOTIFY*/
    0x3d, /*BT_HCI_EVT_REMOTE_HOST_FEATURES_NOTIFY*/
    0x3e, /*BT_HCI_EVT_LE_META_EVENT*/
    0x40, /*BT_HCI_EVT_PHY_LINK_COMPLETE*/
    0x41, /*BT_HCI_EVT_CHANNEL_SELECTED*/
    0x42, /*BT_HCI_EVT_DISCONN_PHY_LINK_COMPLETE*/
    0x43, /*BT_HCI_EVT_PHY_LINK_LOSS_EARLY_WARNING*/
    0x44, /*BT_HCI_EVT_PHY_LINK_RECOVERY*/
    0x45, /*BT_HCI_EVT_LOGIC_LINK_COMPLETE*/
    0x46, /*BT_HCI_EVT_DISCONN_LOGIC_LINK_COMPLETE*/
    0x47, /*BT_HCI_EVT_FLOW_SPEC_MODIFY_COMPLETE*/
    0x48, /*BT_HCI_EVT_NUM_COMPLETED_DATA_BLOCKS*/
    0x4c, /*BT_HCI_EVT_SHORT_RANGE_MODE_CHANGE*/
    0x4d, /*BT_HCI_EVT_AMP_STATUS_CHANGE*/
    0x4e, /*BT_HCI_EVT_TRIGGERED_CLOCK_CAPTURE*/
    0x4f, /*BT_HCI_EVT_SYNC_TRAIN_COMPLETE*/
    0x50, /*BT_HCI_EVT_SYNC_TRAIN_RECEIVED*/
    0x51, /*BT_HCI_EVT_PERIPHERAL_BROADCAST_RECEIVE*/
    0x52, /*BT_HCI_EVT_PERIPHERAL_BROADCAST_TIMEOUT*/
    0x53, /*BT_HCI_EVT_TRUNCATED_PAGE_COMPLETE*/
    0x54, /*BT_HCI_EVT_PERIPHERAL_PAGE_RESPONSE_TIMEOUT*/
    0x55, /*BT_HCI_EVT_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE*/
    0x56, /*BT_HCI_EVT_INQUIRY_RESPONSE_NOTIFY*/
    0x57, /*BT_HCI_EVT_AUTH_PAYLOAD_TIMEOUT_EXPIRED*/
    0x01, /*BT_HCI_EVT_LE_CONN_COMPLETE*/
    0x02, /*BT_HCI_EVT_LE_ADV_REPORT*/
    0x03, /*BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE*/
    0x04, /*BT_HCI_EVT_LE_REMOTE_FEATURES_COMPLETE*/
    0x05, /*BT_HCI_EVT_LE_LONG_TERM_KEY_REQUEST*/
    0x06, /*BT_HCI_EVT_LE_CONN_PARAM_REQUEST*/
    0x07, /*BT_HCI_EVT_LE_DATA_LENGTH_CHANGE*/
    0x08, /*BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE*/
    0x09, /*BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE*/
    0x0a, /*BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE*/
    0x0b, /*BT_HCI_EVT_LE_DIRECT_ADV_REPORT*/
    0x0c, /*BT_HCI_EVT_LE_PHY_UPDATE_COMPLETE*/
    0x0d, /*BT_HCI_EVT_LE_EXT_ADV_REPORT*/
    0x0e, /*BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED*/
    0x0f, /*BT_HCI_EVT_LE_PA_REPORT*/
    0x10, /*BT_HCI_EVT_LE_PA_SYNC_LOST*/
    0x12, /*BT_HCI_EVT_LE_ADV_SET_TERM*/
    0x13, /*BT_HCI_EVT_LE_SCAN_REQ_RECEIVED*/
    0x14, /*BT_HCI_EVT_LE_CHAN_SELECT_ALG*/
    0x17, /*BT_HCI_EVT_LE_CTE_REQUEST_FAILED*/
    0x18, /*BT_HCI_EVT_LE_PA_SYNC_TRANS_REC*/
    0x19, /*BT_HCI_EVT_LE_CIS_ESTABLISHED*/
    0x1a, /*BT_HCI_EVT_LE_CIS_REQ*/
    0x1b, /*BT_HCI_EVT_LE_BIG_COMPLETE*/
    0x1c, /*BT_HCI_EVT_LE_BIG_TERMINATE*/
    0x1d, /*BT_HCI_EVT_LE_BIG_SYNC_ESTABILISHED*/
    0x1e, /*BT_HCI_EVT_LE_BIG_SYNC_LOST*/
    0x1f, /*BT_HCI_EVT_LE_REQ_PEER_SCA_COMPLETE*/
};

extern "C" u32 bt_hci_event_nr()
{
    return sEvt.size();
}

extern "C" u32 bt_hci_le_event_nr() {
    return sLeEvt.size();
}

static void parse_status_evt_handler_btstack(Module *m)
{
    Function *F = m->getFunction("handle_command_status_event");
    for (BasicBlock &BB : F->getBasicBlockList())
    {
        for (Instruction &inst : BB.getInstList())
        {
            if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst))
            {
                int n = sw->getNumCases();
                for (auto c : sw->cases())
                {
                    u16 opcode = c.getCaseValue()->getZExtValue();
                    sStatusCmd.insert(opcode);
                }
                return;
            }
        }
    }
}

static void parse_complete_evt_handler_btstack(Module *m)
{
    Function *F = m->getFunction("handle_command_complete_event");
    for (BasicBlock &BB : F->getBasicBlockList())
    {
        for (Instruction &inst : BB.getInstList())
        {
            if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst))
            {
                int n = sw->getNumCases();
                for (auto c : sw->cases())
                {
                    u16 opcode = c.getCaseValue()->getZExtValue();
                    sCompleteCmd.insert(opcode);
                }
                return;
            }
        }
    }
}

static void parse_le_evt_handler_btstack(BasicBlock *BB)
{
    for (Instruction &inst : BB->getInstList())
    {
        if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst))
        {
            int n = sw->getNumCases();
            for (SwitchInst::CaseHandle &c : sw->cases())
            {
                u8 opcode = c.getCaseValue()->getZExtValue();
                sLeEvt.insert(opcode);
            }
            return;
        }
    }
}

void parse_event_handler_btstack(Module *m)
{
    parse_complete_evt_handler_btstack(m);
    parse_status_evt_handler_btstack(m);

    Function *F = m->getFunction("event_handler");
    for (BasicBlock &BB : F->getBasicBlockList())
    {
        for (Instruction &inst : BB.getInstList())
        {
            if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst))
            {
                int n = sw->getNumCases();
                for (SwitchInst::CaseHandle &c : sw->cases())
                {
                    u8 opcode = c.getCaseValue()->getZExtValue();
                    if(hci_evts.find(opcode) != hci_evts.end())
                        sEvt.insert(opcode);
                    if (opcode == BT_HCI_EVT_LE_META_EVENT)
                    {
                        BasicBlock *bb_le = c.getCaseSuccessor();
                        parse_le_evt_handler_btstack(bb_le);
                    }
                }
                return;
            }
        }
    }
}

void parse_event_handler_nimble(Module* m)
{
    ConstantArray* evt_arr = dyn_cast<ConstantArray>(m->getGlobalVariable("ble_hs_hci_evt_dispatch", true)->getInitializer());
    ConstantArray* le_evt_arr = dyn_cast<ConstantArray>(m->getGlobalVariable("ble_hs_hci_evt_le_dispatch", true)->getInitializer());

    for(int i=0,n=evt_arr->getNumOperands();i!=n;++i)
    {
        Constant* elem = evt_arr->getOperand(i);
        ConstantStruct* st = dyn_cast<ConstantStruct>(elem);
        u8 opcode = dyn_cast<ConstantInt>(st->getOperand(0))->getZExtValue();
        if(hci_evts.find(opcode) != hci_evts.end())
            sEvt.insert(opcode);
    }

    for(int i=0,n=le_evt_arr->getNumOperands();i!=n;++i)
    {
        Constant* elem = le_evt_arr->getOperand(i);
        if(!isa<ConstantPointerNull>(elem))
            sLeEvt.insert(i);
    }
}

/*
void dump_stack_evts()
{
    llvm::outs() << "Events:\n";
    for (uint8_t opcode : stack_evts)
        llvm::outs() << "\t" << get_evt_str(opcode) << "\n";

    llvm::outs() << "LE Events:\n";
    for (uint16_t opcode : stack_le_evts)
        llvm::outs() << "\t" << get_le_evt_str(opcode) << "\n";

    llvm::outs() << "Complete Events:\n";
    for (uint16_t opcode : stack_complete_cmds)
        llvm::outs() << "\t" << get_cmd_str(opcode) << "\n";

    llvm::outs() << "Status Events:\n";
    for (uint16_t opcode : stack_status_cmds)
        llvm::outs() << "\t" << get_cmd_str(opcode) << "\n";
}
*/


extern "C" void init_stack_hci(const char *bc, const char* stack)
{
    SMDiagnostic Err;
    unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
    unique_ptr<Module> M = parseIRFile(bc, Err, *cxt);

    if(strcmp(stack, BTSTACK) == 0)
        parse_event_handler_btstack(M.get());
    else
        parse_event_handler_nimble(M.get());

    std::copy(sEvt.begin(), sEvt.end(), std::back_inserter(vEvt));
    std::copy(sLeEvt.begin(), sLeEvt.end(), std::back_inserter(vLeEvt));
}

/*
int main(int argc, char **argv)
{
    if (argc != 2)
        return 0;

    SMDiagnostic Err;
    unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
    unique_ptr<Module> M = parseIRFile(argv[1], Err, *cxt);
    parse_event_handler_btstack(M.get());
    dump_stack_evts();
    return 0;
}
*/

