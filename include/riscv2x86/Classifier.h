#pragma once
#include "Report.h"
#include <memory>
#include <clang/Tooling/Tooling.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

namespace riscv2x86 {

class Classifier {
public:
    Classifier();
    ~Classifier();

    ClassificationReport &getReport() { return report_; }

    void registerMatchers(clang::ast_matchers::MatchFinder &finder);

private:
    ClassificationReport report_;

    class AsmStmtCallback;
    class FileScopeAsmCallback;
    class TargetBuiltinCallback;
    class GlobalRegVarCallback;

    std::unique_ptr<AsmStmtCallback> asmCb_;
    std::unique_ptr<FileScopeAsmCallback> fileAsmCb_;
    std::unique_ptr<TargetBuiltinCallback> builtinCb_;
    std::unique_ptr<GlobalRegVarCallback> globalRegCb_;
};

} // namespace riscv2x86