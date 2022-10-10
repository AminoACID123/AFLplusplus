#ifndef HCI_ANALYZE_H
#define HCI_ANALYZE_H

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

struct hci_info {
  std::string name;
  uint16_t opcode;
  uint32_t size;
  std::map<int, int> fields;
  std::map<int, int> rsp;
};

class HCIVisitor : public clang::RecursiveASTVisitor<HCIVisitor> {
public:
  explicit HCIVisitor(clang::ASTContext *Context) : Context(Context) {}
  bool TraverseCXXRecordDecl(clang::CXXRecordDecl *decl);
private:
  clang::ASTContext *Context;
  clang::RecordDecl *current_record;
  std::map<std::string, clang::CXXRecordDecl*> DeclMap;
  void parse_fields(std::map<uint32_t,uint16_t>& fields, clang::CXXRecordDecl* decl);
  void parse_field(std::map<uint32_t, uint16_t>& fileds, clang::FieldDecl* decl);
};

class ExtractHCIConsumer : public clang::ASTConsumer {
public:
  explicit ExtractHCIConsumer(clang::ASTContext *Context) : Visitor(Context) {}
  void HandleTranslationUnit(clang::ASTContext &Context);

private:
  HCIVisitor Visitor;
};

class HCIMacroCallback : public clang::PPCallbacks {
public:
  HCIMacroCallback(clang::SourceManager *sm) { SM = sm; }
  void MacroDefined(const clang::Token &MacroNameTok, const clang::MacroDirective *MD);
private:
  clang::SourceManager *SM;
};

class ExtractHCIAction : public clang::ASTFrontendAction {
public:
    std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &Compiler, llvm::StringRef InFile);
};


#endif