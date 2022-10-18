#include "hci.h"
#include "util.h"
#include <bits/unique_ptr.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <set>

using namespace llvm;
using namespace std;

set<uint8_t> stack_evts;
set<uint16_t> stack_le_evts;
set<uint16_t> stack_status_cmds;
set<uint16_t> stack_complete_cmds;

extern "C" bool reply_with_status(uint16_t opcode)
{
    return stack_status_cmds.find(opcode) != stack_status_cmds.end();
}

extern "C" bool reply_with_complete(uint16_t opcode)
{
    return stack_complete_cmds.find(opcode) != stack_complete_cmds.end();
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
                    uint16_t opcode = c.getCaseValue()->getZExtValue();
                    if (get_cmd_str(opcode)[0] != '\0')
                        stack_status_cmds.insert(opcode);
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
                    uint16_t opcode = c.getCaseValue()->getZExtValue();
                    if (get_cmd_str(opcode)[0] != '\0')
                        stack_complete_cmds.insert(opcode);
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
                uint16_t opcode = c.getCaseValue()->getZExtValue();
                stack_le_evts.insert(opcode);
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
                    uint8_t opcode = c.getCaseValue()->getZExtValue();
                    if (get_evt_str(opcode)[0] != '\0')
                        stack_evts.insert(opcode);
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

extern "C" bool complete_reply(uint16_t cmd)
{
    return stack_complete_cmds.find(cmd) != stack_complete_cmds.end();
}

extern "C" bool status_reply(uint16_t cmd)
{
    return stack_status_cmds.find(cmd) != stack_status_cmds.end();
}

extern "C" void init_stack_hci(const char *bc)
{
    SMDiagnostic Err;
    unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
    unique_ptr<Module> M = parseIRFile(bc, Err, *cxt);
    parse_event_handler_btstack(M.get());
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

