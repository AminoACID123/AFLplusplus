#include <bits/unique_ptr.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <set>
#include <vector>

using namespace llvm;
using namespace std;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define BT_HCI_EVT_LE_META_EVENT 0x3e

set<u8> sEvt;
set<u8> sLeEvt;
set<u16> sStatusCmd;
set<u16> sCompleteCmd;

vector<u8> vEvt;
vector<u8> vLeEvt;
vector<u16> vStatusCmd;
vector<u16> vCompleteCmd;

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


extern "C" void init_stack_hci(const char *bc)
{
    SMDiagnostic Err;
    unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
    unique_ptr<Module> M = parseIRFile(bc, Err, *cxt);
    parse_event_handler_btstack(M.get());

    std::copy(vEvt.begin(), vEvt.end(), std::back_inserter(sEvt));
    std::copy(vLeEvt.begin(), vLeEvt.end(), std::back_inserter(sLeEvt));
    std::copy(vStatusCmd.begin(), vStatusCmd.end(), std::back_inserter(sStatusCmd)); 
    std::copy(vCompleteCmd.begin(), vCompleteCmd.end(), std::back_inserter(sCompleteCmd));  
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

