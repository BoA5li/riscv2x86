#include "riscv2x86/Classifier.h"
#include "riscv2x86/RuleEngine.h"
#include "riscv2x86/Rewriter.h"
#include "riscv2x86/Report.h"

#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>
#include <iostream>

using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory ToolCat("riscv2x86 options");

static cl::opt<std::string> OutputDir(
    "o",
    cl::desc("Output directory"),
    cl::value_desc("dir"),
    cl::cat(ToolCat),
    cl::Required);

static cl::opt<std::string> SourceRoot(
    "src-root",
    cl::desc("Source project root (for copy & rewrite)"),
    cl::value_desc("dir"),
    cl::cat(ToolCat),
    cl::Required);

static cl::opt<std::string> ReportJson(
    "report-json",
    cl::desc("Path to dump JSON report"),
    cl::init("riscv2x86_report.json"),
    cl::cat(ToolCat));

static cl::opt<bool> ApplyOnly(
    "apply",
    cl::desc("Apply replacements from --report into source root"),
    cl::cat(ToolCat));

static cl::opt<std::string> ApplyReport(
    "report",
    cl::desc("Translated report.json to apply"),
    cl::cat(ToolCat));

static cl::opt<bool> NoRules(
    "no-builtin-rules",
    cl::desc("Disable built-in C++ rule engine (let external pipeline do translation)"),
    cl::cat(ToolCat));

static cl::opt<bool> AnalysisOnly(
    "analysis-only",
    cl::desc("Analyze and emit report only; do not run builtin rules or rewrite"),
    cl::cat(ToolCat));

int main(int argc, const char **argv) {
    auto OptsExpected = CommonOptionsParser::create(
        argc, argv, ToolCat, llvm::cl::ZeroOrMore, nullptr);

    if (!OptsExpected) {
        llvm::errs() << llvm::toString(OptsExpected.takeError()) << "\n";
        return 1;
    }

    CommonOptionsParser &OptionsParser = OptsExpected.get();
    const auto &SourcePaths = OptionsParser.getSourcePathList();

    if (ApplyOnly && AnalysisOnly) {
        std::cerr << "--apply and --analysis-only cannot be used together\n";
        return 1;
    }

    // ---------- apply mode ----------
    if (ApplyOnly) {
        if (!SourcePaths.empty()) {
            std::cerr << "[riscv2x86] warning: source files are ignored in --apply mode\n";
        }
        if (ApplyReport.empty()) {
            std::cerr << "--apply requires --report=<file>\n";
            return 1;
        }

        riscv2x86::ClassificationReport rep;
        if (!riscv2x86::loadReportJSON(ApplyReport, rep)) {
            std::cerr << "failed to load " << ApplyReport << "\n";
            return 1;
        }

        riscv2x86::SourceRewriter rw(SourceRoot, OutputDir);
        int n = rw.rewrite(rep);
        std::cout << "[riscv2x86] applied " << n
                  << " rewrites into " << OutputDir << "\n";
        return 0;
    }

    // ---------- normal analysis / rewrite mode ----------
    if (SourcePaths.empty()) {
        std::cerr << "no source files provided\n";
        return 1;
    }

    ClangTool Tool(OptionsParser.getCompilations(), SourcePaths);

    riscv2x86::Classifier classifier;
    clang::ast_matchers::MatchFinder Finder;
    classifier.registerMatchers(Finder);

    int rc = Tool.run(newFrontendActionFactory(&Finder).get());
    if (rc != 0) {
        std::cerr << "[riscv2x86] clang tool returned " << rc
                  << " (continuing with partial results)\n";
    }

    // Analysis-only suppresses source writes, not safe Phase 1/2 public
    // replacement classification.  The Python backend must receive these
    // ReplaceableByRule findings so they bypass the asm semantic pipeline.
    if (!NoRules) {
        riscv2x86::RuleEngine eng;
        eng.loadBuiltinRules();
        eng.apply(classifier.getReport());
    }

    classifier.getReport().dumpText(std::cout);
    classifier.getReport().dumpJSON(ReportJson);

    if (AnalysisOnly) {
        std::cout << "[riscv2x86] analysis-only: report written to "
                  << ReportJson << "\n";
        return 0;
    }

    riscv2x86::SourceRewriter rw(SourceRoot, OutputDir);
    int n = rw.rewrite(classifier.getReport());
    std::cout << "[riscv2x86] applied " << n
              << " rewrites into " << OutputDir << "\n";

    return 0;
}
