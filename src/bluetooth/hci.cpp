#include "hci.h"
#include <bits/unique_ptr.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

using namespace llvm;
using namespace std;


void parseEventHandlerBTStack(Module* m){
    Function* F = m->getFunction("event_handler");
    assert(F != nullptr);
    
    for(BasicBlock& BB : F->getBasicBlockList()){
        for(Instruction& inst : BB.getInstList()){
            if(SwitchInst* sw = dyn_cast<SwitchInst>(&inst)){
                int n = sw->getNumCases();
                for(auto c : sw->cases()){
                    llvm::outs() << c.getCaseValue()->getZExtValue() << "\n";
                }
            }
        }
    }

    F = m->getFunction("handle_command_complete_event");
    for(BasicBlock& BB : F->getBasicBlockList()){
        for(Instruction& inst : BB.getInstList()){
            if(SwitchInst* sw = dyn_cast<SwitchInst>(&inst)){
                int n = sw->getNumCases();
                for(auto c : sw->cases()){
                    llvm::outs() << c.getCaseValue()->getZExtValue() << "\n";
                }
            }
        }
    }

    F = m->getFunction("handle_command_status_event");
    for(BasicBlock& BB : F->getBasicBlockList()){
        for(Instruction& inst : BB.getInstList()){
            if(SwitchInst* sw = dyn_cast<SwitchInst>(&inst)){
                int n = sw->getNumCases();
                for(auto c : sw->cases()){
                    llvm::outs() << c.getCaseValue()->getZExtValue() << "\n";
                }
            }
        }
    }
}

int main(int argc, char** argv){
    if(argc != 2)
        return 0;

    unique_ptr<LLVMContext> cxt = make_unique<LLVMContext>();
    SMDiagnostic Err;
    unique_ptr<Module> M = parseIRFile(argv[1], Err, *cxt);
    parseEventHandlerBTStack(M.get());
    return 0;
}


