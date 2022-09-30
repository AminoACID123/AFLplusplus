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

static void parseStatusEvtHandlerBTStack(Module *m) {
  Function *F = m->getFunction("handle_command_status_event");
  for (BasicBlock &BB : F->getBasicBlockList()) {
    for (Instruction &inst : BB.getInstList()) {
      if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst)) {
        int n = sw->getNumCases();
        for (auto c : sw->cases()) {
          stack_status_cmds.insert(c.getCaseValue()->getZExtValue());
        }
        return;
      }
    }
  }
}

static void parseCompleteEvtHandlerBTStack(Module *m) {
  Function *F = m->getFunction("handle_command_complete_event");
  for (BasicBlock &BB : F->getBasicBlockList()) {
    for (Instruction &inst : BB.getInstList()) {
      if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst)) {
        int n = sw->getNumCases();
        for (auto c : sw->cases()) {
          stack_complete_cmds.insert(c.getCaseValue()->getZExtValue());
        }
        return;
      }
    }
  }
}

static void parseLeEvtHandlerBTStack(BasicBlock *BB) {
  for (Instruction &inst : BB->getInstList()) {
    if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst)) {
      int n = sw->getNumCases();
      for (SwitchInst::CaseHandle &c : sw->cases()) {
        uint16_t opcode = c.getCaseValue()->getZExtValue();
        stack_le_evts.insert(opcode);
      }
      return;
    }
  }
}

void parseEventHandlerBTStack(Module *m) {

  parseCompleteEvtHandlerBTStack(m);
  parseStatusEvtHandlerBTStack(m);

  Function *F = m->getFunction("event_handler");
  for (BasicBlock &BB : F->getBasicBlockList()) {
    for (Instruction &inst : BB.getInstList()) {
      if (SwitchInst *sw = dyn_cast<SwitchInst>(&inst)) {
        int n = sw->getNumCases();
        for (SwitchInst::CaseHandle &c : sw->cases()) {
          uint8_t opcode = c.getCaseValue()->getZExtValue();
          stack_evts.insert(opcode);
          if (opcode == BT_HCI_EVT_LE_META_EVENT) {
            BasicBlock *bb_le = c.getCaseSuccessor();
            parseLeEvtHandlerBTStack(bb_le);
          }
        }
        return;
      }
    }
  }
}

void dumpStackEvts(){
    llvm::outs() << "Events:\n";
    for(uint8_t opcode : stack_evts)
        llvm::outs() << "\t" << get_evt_str(opcode) << "\n";

    llvm::outs()<< "LE Events:\n";
    for(uint16_t opcode : stack_le_evts)
        llvm::outs() << "\t" << get_le_evt_str(opcode) << "\n";

    llvm::outs()<< "Complete Events:\n";
    for(uint16_t opcode : stack_complete_cmds)
        llvm::outs() << "\t" << get_cmd_str(opcode) << "\n";

    llvm::outs()<< "Status Events:\n";
    for(uint16_t opcode : stack_status_cmds)
        llvm::outs() << "\t" << get_cmd_str(opcode) << "\n";
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 0;

  unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
  SMDiagnostic Err;
  unique_ptr<Module> M = parseIRFile(argv[1], Err, *cxt);
  parseEventHandlerBTStack(M.get());
  dumpStackEvts();
  return 0;
}
