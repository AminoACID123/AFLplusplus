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

set<u8> _stack_evts;
set<u8> _stack_le_evts;
set<u16> _stack_status_cmds;
set<u16> _stack_complete_cmds;

vector<u8> stack_evts;
vector<u8> stack_le_evts;
vector<u16> stack_status_cmds;
vector<u16> stack_complete_cmds;

extern "C" bool reply_with_status(u16 opcode)
{
    return _stack_status_cmds.find(opcode) != _stack_status_cmds.end();
}

extern "C" bool reply_with_complete(u16 opcode)
{
    return _stack_complete_cmds.find(opcode) != _stack_complete_cmds.end();
}

extern "C" u32 get_total_hci() {
    return stack_evts.size();
}

extern "C" u32 get_total_hci_le() {
    return stack_le_evts.size();
}

extern "C" void generate_random_hci(u32 seed, u8* evt, u8* le_evt) {
   *evt =  stack_evts[(seed >> 16) % stack_evts.size()];
   if(*evt == BT_HCI_EVT_LE_META_EVENT)
    *le_evt = stack_le_evts[seed % stack_le_evts.size()];
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
                    _stack_status_cmds.insert(opcode);
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
                    _stack_complete_cmds.insert(opcode);
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
                _stack_le_evts.insert(opcode);
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
                    _stack_evts.insert(opcode);
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


extern "C" bool complete_reply(u16 cmd)
{
    return _stack_complete_cmds.find(cmd) != _stack_complete_cmds.end();
}

extern "C" bool status_reply(u16 cmd)
{
    return _stack_status_cmds.find(cmd) != _stack_status_cmds.end();
}


extern "C" void init_stack_hci(const char *bc)
{
    SMDiagnostic Err;
    unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
    unique_ptr<Module> M = parseIRFile(bc, Err, *cxt);
    parse_event_handler_btstack(M.get());

    std::copy(_stack_evts.begin(), _stack_evts.end(), std::back_inserter(stack_evts));
    std::copy(_stack_le_evts.begin(), _stack_le_evts.end(), std::back_inserter(stack_le_evts));
    std::copy(_stack_status_cmds.begin(), _stack_status_cmds.end(), std::back_inserter(stack_status_cmds)); 
    std::copy(_stack_complete_cmds.begin(), _stack_complete_cmds.end(), std::back_inserter(stack_status_cmds));  
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

