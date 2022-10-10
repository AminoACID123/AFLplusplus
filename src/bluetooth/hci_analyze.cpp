#include "hci_analyze.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include <map>
#include <sstream>
#include <stdint.h>
#include <string>
#include <vector>

using namespace llvm;
using namespace clang;
using namespace clang::tooling;

// Apply a custom category to all command-line options so that they are the
// only ones displayed.
static cl::OptionCategory MyToolCategory("my-tool options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
static cl::extrahelp MoreHelp("\nMore help text...\n");

std::map<uint16_t, hci_info> hci_cmds;
std::map<uint16_t, hci_info> hci_evts;
std::map<uint16_t, hci_info> hci_le_evts;

std::map<std::string, uint16_t> name_to_hci_cmd;
std::map<std::string, uint16_t> name_to_hci_evt;
std::map<std::string, uint16_t> name_to_hci_le_evt;

bool HCIVisitor::TraverseCXXRecordDecl(CXXRecordDecl *decl) {
  StringRef name = decl->getName();
  DeclMap["struct " + name.str()] = decl;
  if (name.find("bt_hci_cmd") == name.npos &&
      name.find("bt_hci_evt") == name.npos)
    return true;
  if (name == "bt_hci_cmd_hdr" || name == "bt_hci_evt_hdr")
    return true;

  uint16_t opcode;
  std::map<int, int> *fields = nullptr;
  if (name.find("bt_hci_cmd") != name.npos) {
    opcode = name_to_hci_cmd[name.upper()];
    fields = &hci_cmds[opcode].fields;
  } else if (name.find("bt_hci_evt_le") != name.npos) {
    opcode = name_to_hci_le_evt[name.upper()];
    fields = &hci_le_evts[opcode].fields;
  } else if (name.find("bt_hci_evt") != name.npos) {
    opcode = name_to_hci_evt[name.upper()];
    fields = &hci_evts[opcode].fields;
  } else if (name.find("bt_hci_rsp") != name.npos) {
    StringRef cmd = StringRef("bt_hci_cmd_" + name.substr(11).str()).upper();
    opcode = name_to_hci_cmd[cmd.str()];
    fields = &hci_cmds[opcode].rsp;
  }
  if (fields != nullptr)
    parse_fields(*fields, decl);
  return true;
}

void HCIVisitor::parse_fields(std::map<int, int> &fields, CXXRecordDecl *decl) {
  int offset;
  if (fields.size() == 0)
    offset = 0;
  else
    offset = fields.rbegin()->first + fields.rbegin()->second;

  for (FieldDecl *FD : decl->fields()) {
    const clang::Type *T = FD->getType().getTypePtr();
    std::string Tname = FD->getType().getAsString();
    if (T->isStructureType()) {
      parse_fields(fields,T->getAsCXXRecordDecl());
    } else {
      parse_field(fields, FD);
    }
  }
}

void HCIVisitor::parse_field(std::map<int,int>& fields, FieldDecl* FD){
    const clang::Type *T = FD->getType().getTypePtr();
    std::string Tname = FD->getType().getAsString();
    
}

void ExtractHCIConsumer::HandleTranslationUnit(clang::ASTContext &Context) {
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());
}

void HCIMacroCallback::MacroDefined(const Token &MacroNameTok,
                                    const MacroDirective *MD) {
  std::string macro = MacroNameTok.getIdentifierInfo()->getName().str();
  if (macro.find("BT_HCI_CMD") == macro.npos &&
      macro.find("BT_HCI_EVT") == macro.npos)
    return;
  if (macro == "BT_HCI_CMD_BIT" || macro == "BT_HCI_CMD_NOP")
    return;

  LangOptions opt;
  std::stringstream ss;
  uint16_t opcode;
  const Token &OpcodeTok = MD->getMacroInfo()->getReplacementToken(0);
  SourceRange Range(OpcodeTok.getLocation(), OpcodeTok.getEndLoc());
  CharSourceRange CRange(Range, false);
  ss << Lexer::getSourceText(CRange, *SM, opt).str() << std::hex;
  ss >> opcode;

  if (macro.find("BT_HCI_CMD") != macro.npos) {
    hci_cmds[opcode].name = macro;
    name_to_hci_cmd[macro] = opcode;
  } else if (macro.find("BT_HCI_EVT_LE") != macro.npos) {
    hci_le_evts[opcode].name = macro;
    name_to_hci_le_evt[macro] = opcode;
  } else if (macro.find("BT_EVT") != macro.npos) {
    hci_evts[opcode].name = macro;
    name_to_hci_evt[macro] = opcode;
  }
}

std::unique_ptr<clang::ASTConsumer>
ExtractHCIAction::CreateASTConsumer(clang::CompilerInstance &Compiler,
                                    llvm::StringRef InFile) {
  std::unique_ptr<HCIMacroCallback> C(
      new HCIMacroCallback(&Compiler.getSourceManager()));
  Compiler.getPreprocessor().addPPCallbacks(std::move(C));
  return std::make_unique<ExtractHCIConsumer>(&Compiler.getASTContext());
}

int main(int argc, const char **argv) {
  auto ExpectedParser = clang::tooling::CommonOptionsParser::create(
      argc, argv, MyToolCategory, llvm::cl::NumOccurrencesFlag::Required);
  if (!ExpectedParser) {
    // Fail gracefully for unsupported options.
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }

  CommonOptionsParser &OptionsParser = ExpectedParser.get();
  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());

  return Tool.run(newFrontendActionFactory<ExtractHCIAction>().get());
}