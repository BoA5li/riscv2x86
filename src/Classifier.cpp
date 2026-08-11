#include "riscv2x86/Classifier.h"
#include <clang/AST/ASTContext.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Lex/Lexer.h>
#include <sstream>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <regex>

using namespace clang;
using namespace clang::ast_matchers;
using namespace riscv2x86;

namespace {

BuiltinFinding::TypeContract makeTypeContract(QualType type, ASTContext &ctx) {
    BuiltinFinding::TypeContract out;
    const QualType canonical = type.getCanonicalType();
    out.canonicalType = canonical.getAsString();
    out.isPointer = canonical->isPointerType();
    out.isSigned = canonical->isSignedIntegerType();
    out.alignmentBytes = static_cast<unsigned>(ctx.getTypeAlignInChars(type).getQuantity());
    out.qualifiers = canonical.getQualifiers().getAsString();
    if (!canonical->isVoidType() && !canonical->isFunctionType())
        out.widthBits = static_cast<unsigned>(ctx.getTypeSize(canonical));
    if (out.isPointer)
        out.pointeeCanonicalType = canonical->getPointeeType().getCanonicalType().getAsString();
    return out;
}

std::string makeFragmentId(const std::string &file, unsigned line, unsigned col) {
    std::ostringstream os;
    os << file << ":" << line << ":" << col;
    return os.str();
}

std::string getEnclosingFunctionName(const Stmt *S, ASTContext &Ctx) {
    auto parents = Ctx.getParents(*S);
    while (!parents.empty()) {
        const auto &p = parents[0];
        if (const auto *FD = p.get<FunctionDecl>())
            return FD->getNameAsString();
        parents = Ctx.getParents(p);
    }
    return "<file-scope>";
}

static std::string trimCopy(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

static bool isMatchingConstraintAlt(const std::string &alt) {
    std::string s = trimCopy(alt);
    if (s.empty()) return false;

    if (std::isdigit(static_cast<unsigned char>(s[0])))
        return true;

    if (s[0] == '[') {
        size_t r = s.find(']');
        return r != std::string::npos && r > 1;
    }

    return false;
}

static bool isGlobalRegisterVariable(const VarDecl *VD) {
    if (!VD) return false;
    if (!VD->isFileVarDecl()) return false;
    if (VD->getStorageClass() != SC_Register) return false;
    if (!VD->hasAttr<AsmLabelAttr>()) return false;
    return true;
}

static bool isTiedInputConstraint(const std::string &constraint) {
    std::string s = trimCopy(constraint);
    if (s.empty()) return false;

    size_t start = 0;
    while (start < s.size()) {
        size_t comma = s.find(',', start);
        std::string alt = s.substr(start, comma == std::string::npos ? std::string::npos
                                                                     : comma - start);
        if (isMatchingConstraintAlt(alt))
            return true;

        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

static bool hasEarlyClobberModifier(const std::string &constraint) {
    std::string s = trimCopy(constraint);
    if (s.empty()) return false;

    size_t start = 0;
    while (start < s.size()) {
        size_t comma = s.find(',', start);
        std::string alt = trimCopy(s.substr(start, comma == std::string::npos ? std::string::npos
                                                                              : comma - start));

        for (char c : alt) {
            if (c == '&') return true;
            if (!(c == '=' || c == '+' || c == '&' || c == '%' ||
                  std::isspace(static_cast<unsigned char>(c))))
                break;
        }

        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

SourceLocation getLocAfterToken(SourceLocation loc,
                                SourceManager &SM,
                                const LangOptions &LangOpts) {
    return Lexer::getLocForEndOfToken(loc, 0, SM, LangOpts);
}

unsigned getTokenEndOffset(SourceLocation endLoc,
                           SourceManager &SM,
                           const LangOptions &LangOpts) {
    SourceLocation afterTok = getLocAfterToken(endLoc, SM, LangOpts);
    if (afterTok.isInvalid()) {
        return SM.getFileOffset(endLoc);
    }
    return SM.getFileOffset(afterTok);
}

// 语句式片段结束 offset：会吸收 ';'
unsigned getStmtLikeEndOffsetIncludingSemi(SourceLocation endLoc,
                                           SourceManager &SM,
                                           const LangOptions &LangOpts) {
    SourceLocation spellingEnd = SM.getSpellingLoc(endLoc);
    SourceLocation afterTok = getLocAfterToken(spellingEnd, SM, LangOpts);
    if (afterTok.isInvalid()) {
        return SM.getFileOffset(spellingEnd);
    }

    FileID fid = SM.getFileID(afterTok);
    bool invalid = false;
    StringRef buffer = SM.getBufferData(fid, &invalid);
    if (invalid) {
        return SM.getFileOffset(afterTok);
    }

    unsigned offset = SM.getFileOffset(afterTok);
    if (offset > buffer.size()) {
        return static_cast<unsigned>(buffer.size());
    }

    unsigned i = offset;
    while (i < buffer.size()) {
        char c = buffer[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++i;
            continue;
        }
        if (c == ';') {
            ++i;
        }
        break;
    }

    return i;
}

static std::string getImmediateMacroNameSafe(SourceLocation loc,
                                             SourceManager &SM,
                                             const LangOptions &LangOpts) {
    if (loc.isInvalid() || !loc.isMacroID()) return {};
    return Lexer::getImmediateMacroName(loc, SM, LangOpts).str();
}

static std::string getAnyImmediateMacroName(SourceLocation a,
                                            SourceLocation b,
                                            SourceManager &SM,
                                            const LangOptions &LangOpts) {
    std::string s = getImmediateMacroNameSafe(a, SM, LangOpts);
    if (!s.empty()) return s;
    return getImmediateMacroNameSafe(b, SM, LangOpts);
}

static std::string getBufferSliceByOffsets(SourceLocation anchorLoc,
                                           SourceManager &SM,
                                           unsigned beginOffset,
                                           unsigned endOffset) {
    if (anchorLoc.isInvalid()) return {};
    FileID fid = SM.getFileID(anchorLoc);
    bool invalid = false;
    StringRef buffer = SM.getBufferData(fid, &invalid);
    if (invalid) return {};
    if (endOffset < beginOffset || endOffset > buffer.size()) return {};
    return buffer.substr(beginOffset, endOffset - beginOffset).str();
}

static bool computeRewriteRangeForNode(SourceRange SR,
                                       SourceManager &SM,
                                       const LangOptions &LangOpts,
                                       unsigned &beginOffset,
                                       unsigned &endOffset,
                                       std::string &rawText) {
    CharSourceRange tokRange = CharSourceRange::getTokenRange(SR);
    CharSourceRange fileRange = Lexer::makeFileCharRange(tokRange, SM, LangOpts);
    if (fileRange.isInvalid()) return false;

    SourceLocation B = fileRange.getBegin();
    SourceLocation E = fileRange.getEnd();
    if (B.isInvalid() || E.isInvalid()) return false;
    if (SM.getFileID(B) != SM.getFileID(E)) return false;

    beginOffset = SM.getFileOffset(B);
    endOffset = SM.getFileOffset(E);

    bool invalid = false;
    StringRef buffer = SM.getBufferData(SM.getFileID(B), &invalid);
    if (invalid) return false;
    if (endOffset < beginOffset || endOffset > buffer.size()) return false;

    rawText = buffer.substr(beginOffset, endOffset - beginOffset).str();
    return true;
}

unsigned getTokenLikeEndOffset(SourceLocation endLoc,
                               SourceManager &SM,
                               const LangOptions &LangOpts) {
    SourceLocation spellingEnd = SM.getSpellingLoc(endLoc);
    SourceLocation afterTok = getLocAfterToken(spellingEnd, SM, LangOpts);
    if (afterTok.isInvalid()) {
        return SM.getFileOffset(spellingEnd);
    }
    return SM.getFileOffset(afterTok);
}

std::string getBufferSlice(SourceManager &SM,
                           SourceLocation anyLocInFile,
                           unsigned beginOffset,
                           unsigned endOffset) {
    FileID fid = SM.getFileID(anyLocInFile);
    bool invalid = false;
    StringRef buffer = SM.getBufferData(fid, &invalid);
    if (invalid) return "";

    if (beginOffset > endOffset || endOffset > buffer.size()) return "";
    return buffer.substr(beginOffset, endOffset - beginOffset).str();
}


static std::string getExpansionSourceText(SourceRange SR,
                                          SourceManager &SM,
                                          const LangOptions &LangOpts) {
    SourceLocation B = SM.getExpansionLoc(SR.getBegin());
    SourceLocation E = SM.getExpansionLoc(SR.getEnd());
    if (B.isInvalid() || E.isInvalid()) return "";

    return Lexer::getSourceText(CharSourceRange::getTokenRange(SourceRange(B, E)),
                                SM, LangOpts).str();
}

// 获取 GNU inline asm operand 对应宿主 C/C++ expression 的类型宽度。
//
// 返回值单位为 bit；无法可靠获得静态宽度时返回 std::nullopt。
//
// 这里记录的是 C/C++ expression 的 AST type width，而不是：
// - RISC-V XLEN
// - RISC-V 指令实际使用的寄存器宽度
// - x86 后端最终选择的寄存器宽度
static std::optional<unsigned> getOperandWidthBits(const Expr *E,
                                                    ASTContext &Ctx) {
    if (!E) {
        return std::nullopt;
    }

    QualType type = E->getType();

    if (type.isNull()) {
        return std::nullopt;
    }

    // 模板依赖类型在当前分析阶段没有可确定的实际宽度。
    if (type->isDependentType()) {
        return std::nullopt;
    }

    // void/function/incomplete/VLA 等类型不能安全地作为固定宽度事实导出。
    if (type->isVoidType() ||
        type->isFunctionType() ||
        type->isIncompleteType() ||
        type->isVariablyModifiedType()) {
        return std::nullopt;
    }

    const uint64_t widthBits = Ctx.getTypeSize(type);

    if (widthBits == 0 ||
        widthBits > static_cast<uint64_t>(
                        std::numeric_limits<unsigned>::max())) {
        return std::nullopt;
    }

    return static_cast<unsigned>(widthBits);
}

AsmFragment extractGCCAsm(const GCCAsmStmt *S, ASTContext &Ctx) {
    AsmFragment frag;
    SourceManager &SM = Ctx.getSourceManager();

    SourceLocation beginLoc = SM.getExpansionLoc(S->getBeginLoc());
    SourceLocation endLoc   = SM.getExpansionLoc(S->getEndLoc());

    PresumedLoc PL = SM.getPresumedLoc(beginLoc);

    frag.fileName = PL.isValid() ? PL.getFilename() : "<unknown>";
    frag.line = PL.isValid() ? PL.getLine() : 0;
    frag.column = PL.isValid() ? PL.getColumn() : 0;
    frag.beginOffset = SM.getFileOffset(beginLoc);
    frag.endOffset = getStmtLikeEndOffsetIncludingSemi(endLoc, SM, Ctx.getLangOpts());
    frag.id = makeFragmentId(frag.fileName, frag.line, frag.column);
    frag.enclosingFunction = getEnclosingFunctionName(S, Ctx);
    frag.isVolatile = S->isVolatile();

    // 模板原文
    frag.rawAsmText = S->getAsmString()->getString().str();

    // 输出操作数。
    //
    // GNU operand 编号规则：
    // outputs 总是从 0 开始编号。
    for (unsigned i = 0; i < S->getNumOutputs(); ++i) {
        AsmOperand op;
        op.isOutput = true;
        op.constraint = S->getOutputConstraint(i).str();

        if (const Expr *E = S->getOutputExpr(i)) {
            op.exprText = Lexer::getSourceText(
                CharSourceRange::getTokenRange(E->getSourceRange()),
                SM, Ctx.getLangOpts()).str();

            // 输出 operand 的 GNU 编号就是 i。
            if (const auto widthBits = getOperandWidthBits(E, Ctx)) {
                frag.operandWidthBits[i] = *widthBits;
            }
        }

        op.symbolicName = S->getOutputName(i).str();
        op.isEarlyClobber = hasEarlyClobberModifier(op.constraint);
        frag.outputs.push_back(std::move(op));
    }

    // 输入操作数。
    //
    // GNU operand 编号规则：
    // inputs 的编号在全部 outputs 之后开始。
    const unsigned inputBaseIndex = S->getNumOutputs();

    for (unsigned i = 0; i < S->getNumInputs(); ++i) {
        AsmOperand op;
        op.isOutput = false;
        op.constraint = S->getInputConstraint(i).str();

        if (const Expr *E = S->getInputExpr(i)) {
            op.exprText = Lexer::getSourceText(
                CharSourceRange::getTokenRange(E->getSourceRange()),
                SM, Ctx.getLangOpts()).str();

            // 第 i 个 input 的 GNU operand index：
            //
            //   getNumOutputs() + i
            //
            // 例如：
            //   : "=r"(result)
            //   : "r"(a), "r"(b)
            //
            // result => %0
            // a      => %1
            // b      => %2
            if (const auto widthBits = getOperandWidthBits(E, Ctx)) {
                frag.operandWidthBits[inputBaseIndex + i] = *widthBits;
            }
        }

        op.symbolicName = S->getInputName(i).str();
        op.isTied = isTiedInputConstraint(op.constraint);
        frag.inputs.push_back(std::move(op));
    }

    // clobbers
    for (unsigned i = 0; i < S->getNumClobbers(); ++i) {
        frag.clobbers.push_back(S->getClobber(i).str());
    }

    // asm goto labels
    if (S->isAsmGoto()) {
        frag.kind = AsmKind::InlineGoto;
        frag.asmGotoFallthroughContinuationId =
            "asm-goto:" + frag.id + ":fallthrough";
        frag.asmGotoSuccessorContinuationIds.push_back(
            frag.asmGotoFallthroughContinuationId
        );

        for (unsigned i = 0; i < S->getNumLabels(); ++i) {
            const std::string label = S->getLabelName(i).str();
            const std::string continuationId =
                "asm-goto:" + frag.id + ":label:" + label;
            frag.gotoLabels.push_back(label);
            // Clang has already resolved this identifier as an asm-goto
            // label.  Preserve the binding as source-shell metadata instead
            // of asking Phase 4/6 to infer it from "%l" text.
            frag.gotoEdges.push_back(AsmGotoEdge{
                "%l" + std::to_string(i), label, i, continuationId
            });
            frag.asmGotoSuccessorContinuationIds.push_back(continuationId);
        }
        // Clang has resolved every GCCAsmStmt label before this callback.  The
        // IDs above therefore describe the host-C continuation interface
        // independently of Phase-4 synthetic labels and lifted CFG layout.
        frag.asmGotoControlFlowComplete = !frag.gotoEdges.empty();
        const std::regex beqz(R"(^\s*beqz\s+%(?:0|\[[A-Za-z_][A-Za-z0-9_]*\])\s*,?\s*%l(?:0|\[[A-Za-z_][A-Za-z0-9_]*\])\s*$)");
        const std::regex bnez(R"(^\s*bnez\s+%(?:0|\[[A-Za-z_][A-Za-z0-9_]*\])\s*,?\s*%l(?:0|\[[A-Za-z_][A-Za-z0-9_]*\])\s*$)");
        if (std::regex_match(frag.rawAsmText, beqz)) {
            frag.asmGotoConditionKind = "zero";
            frag.asmGotoConditionOperandIndex = 0;
        } else if (std::regex_match(frag.rawAsmText, bnez)) {
            frag.asmGotoConditionKind = "nonzero";
            frag.asmGotoConditionOperandIndex = 0;
        }
    } else if (S->getNumOutputs() == 0 &&
               S->getNumInputs() == 0 &&
               S->getNumClobbers() == 0) {
        frag.kind = AsmKind::InlineBasic;
    } else {
        frag.kind = AsmKind::InlineExtended;
    }

    return frag;
}

} // anonymous namespace

// ---------- AsmStmtCallback ----------
class Classifier::AsmStmtCallback : public MatchFinder::MatchCallback {
public:
    explicit AsmStmtCallback(ClassificationReport &r) : report_(r) {}

    void run(const MatchFinder::MatchResult &Result) override {
        const auto *S = Result.Nodes.getNodeAs<GCCAsmStmt>("gccAsm");
        if (!S) return;

        ASTContext &Ctx = *Result.Context;
        SourceManager &SM = Ctx.getSourceManager();

        AsmFragment frag = extractGCCAsm(S, Ctx);

        Finding f;
        f.category = Category::NeedsAsmTranslation;
        f.description = "GCC inline asm";
        f.fileName = frag.fileName;
        f.line = frag.line;
        f.column = frag.column;
        f.fragment = frag;

        f.subjectKind = "AsmFragment";
        f.hasRewriteRange = true;
        f.rewriteBeginOffset = frag.beginOffset;
        f.rewriteEndOffset = frag.endOffset;
        f.rawSourceText = getBufferSliceByOffsets(
            SM.getExpansionLoc(S->getBeginLoc()), SM, frag.beginOffset, frag.endOffset);

        f.fromMacroExpansion = S->getBeginLoc().isMacroID() || S->getEndLoc().isMacroID();
        if (f.fromMacroExpansion) {
            f.macroName = getAnyImmediateMacroName(
                S->getBeginLoc(), S->getEndLoc(), SM, Ctx.getLangOpts());
        }

        report_.findings.push_back(std::move(f));
    }

private:
    ClassificationReport &report_;
};

// ---------- FileScopeAsmCallback ----------
class Classifier::FileScopeAsmCallback : public MatchFinder::MatchCallback {
public:
    explicit FileScopeAsmCallback(ClassificationReport &r) : report_(r) {}

    void run(const MatchFinder::MatchResult &Result) override {
        const auto *D = Result.Nodes.getNodeAs<FileScopeAsmDecl>("fileAsm");
        if (!D) return;

        ASTContext &Ctx = *Result.Context;
        SourceManager &SM = Ctx.getSourceManager();

        SourceLocation beginLoc = SM.getExpansionLoc(D->getBeginLoc());
        PresumedLoc PL = SM.getPresumedLoc(beginLoc);

        AsmFragment frag;
        frag.kind = AsmKind::FileScope;
        frag.fileName = PL.isValid() ? PL.getFilename() : "<unknown>";
        frag.line = PL.isValid() ? PL.getLine() : 0;
        frag.column = PL.isValid() ? PL.getColumn() : 0;
        frag.beginOffset = SM.getFileOffset(beginLoc);
        frag.endOffset = getStmtLikeEndOffsetIncludingSemi(
            SM.getExpansionLoc(D->getEndLoc()), SM, Ctx.getLangOpts());
        frag.id = makeFragmentId(frag.fileName, frag.line, frag.column);
        frag.enclosingFunction = "<file-scope>";
        if (D->getAsmString())
            frag.rawAsmText = D->getAsmString()->getString().str();

        Finding f;
        f.category = Category::NeedsAsmTranslation;
        f.description = "File-scope asm";
        f.fileName = frag.fileName;
        f.line = frag.line;
        f.column = frag.column;
        f.fragment = frag;

        f.subjectKind = "AsmFragment";
        f.hasRewriteRange = true;
        f.rewriteBeginOffset = frag.beginOffset;
        f.rewriteEndOffset = frag.endOffset;
        f.rawSourceText = getBufferSliceByOffsets(beginLoc, SM, frag.beginOffset, frag.endOffset);

        report_.findings.push_back(std::move(f));
    }

private:
    ClassificationReport &report_;
};

// ---------- TargetBuiltinCallback ----------
class Classifier::TargetBuiltinCallback : public MatchFinder::MatchCallback {
public:
    explicit TargetBuiltinCallback(ClassificationReport &r) : report_(r) {}

    void run(const MatchFinder::MatchResult &Result) override {
        const auto *CE = Result.Nodes.getNodeAs<CallExpr>("call");
        if (!CE) return;

        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD) return;

        std::string name = FD->getNameAsString();
        if (name.rfind("__builtin_riscv", 0) != 0 &&
            name.rfind("__riscv_", 0) != 0)
            return;

        ASTContext &Ctx = *Result.Context;
        SourceManager &SM = Ctx.getSourceManager();

        SourceLocation beginLoc = SM.getExpansionLoc(CE->getBeginLoc());
        PresumedLoc PL = SM.getPresumedLoc(beginLoc);

        Finding f;
        f.category = Category::NeedsAsmTranslation;
        f.description = "RISC-V target builtin: " + name;
        f.fileName = PL.isValid() ? PL.getFilename() : "<unknown>";
        f.line = PL.isValid() ? PL.getLine() : 0;
        f.column = PL.isValid() ? PL.getColumn() : 0;

        f.subjectKind = "BuiltinCall";
        f.symbolName = name;

        for (const Expr *Arg : CE->arguments()) {
            std::string argText = Lexer::getSourceText(
                CharSourceRange::getTokenRange(Arg->getSourceRange()),
                SM, Ctx.getLangOpts()).str();
            f.arguments.push_back(std::move(argText));
            f.builtin.emplace();
            f.builtin->argumentTypeIds.push_back(
                Arg->getType().getCanonicalType().getAsString()
            );
            f.builtin->argumentTypes.push_back(makeTypeContract(Arg->getType(), Ctx));
        }
        if (!f.builtin.has_value()) f.builtin.emplace();
        f.builtin->calleeName = name;
        f.builtin->args = f.arguments;
        f.builtin->resultTypeId = CE->getType().getCanonicalType().getAsString();
        f.builtin->resultType = makeTypeContract(CE->getType(), Ctx);
        f.builtin->resultIsLValue = CE->isGLValue();

        f.fromMacroExpansion = CE->getBeginLoc().isMacroID() || CE->getEndLoc().isMacroID();
        if (f.fromMacroExpansion) {
            f.subjectKind = "MacroCall";
            f.macroName = getAnyImmediateMacroName(
                CE->getBeginLoc(), CE->getEndLoc(), SM, Ctx.getLangOpts());
        }

        std::string rawText;
        unsigned beginOffset = 0, endOffset = 0;
        if (computeRewriteRangeForNode(CE->getSourceRange(), SM, Ctx.getLangOpts(),
                                    beginOffset, endOffset, rawText)) {
            f.hasRewriteRange = true;
            f.rewriteBeginOffset = beginOffset;
            f.rewriteEndOffset = endOffset;
            f.rawSourceText = std::move(rawText);
        }

        report_.findings.push_back(std::move(f));
    }

private:
    ClassificationReport &report_;
};

// ---------- GlobalRegVarCallback ----------
class Classifier::GlobalRegVarCallback : public MatchFinder::MatchCallback {
public:
    explicit GlobalRegVarCallback(ClassificationReport &r) : report_(r) {}

    void run(const MatchFinder::MatchResult &Result) override {
        const auto *VD = Result.Nodes.getNodeAs<VarDecl>("var");
        if (!VD) return;

        if (!isGlobalRegisterVariable(VD)) return;

        ASTContext &Ctx = *Result.Context;
        SourceManager &SM = Ctx.getSourceManager();
        PresumedLoc PL = SM.getPresumedLoc(VD->getBeginLoc());

        Finding f;
        f.category = Category::Unsupported;
        f.description = "Global register variable: " + VD->getNameAsString();
        f.fileName = PL.isValid() ? PL.getFilename() : "<unknown>";
        f.line = PL.isValid() ? PL.getLine() : 0;
        f.column = PL.isValid() ? PL.getColumn() : 0;
        report_.findings.push_back(std::move(f));
    }

private:
    ClassificationReport &report_;
};

// ---------- Classifier ----------
Classifier::Classifier() {
    asmCb_       = std::make_unique<AsmStmtCallback>(report_);
    fileAsmCb_   = std::make_unique<FileScopeAsmCallback>(report_);
    builtinCb_   = std::make_unique<TargetBuiltinCallback>(report_);
    globalRegCb_ = std::make_unique<GlobalRegVarCallback>(report_);
}

Classifier::~Classifier() = default;

void Classifier::registerMatchers(MatchFinder &finder) {
    finder.addMatcher(stmt().bind("gccAsm"), asmCb_.get());
    finder.addMatcher(decl().bind("fileAsm"), fileAsmCb_.get());
    finder.addMatcher(callExpr().bind("call"), builtinCb_.get());
    finder.addMatcher(varDecl(hasGlobalStorage()).bind("var"), globalRegCb_.get());
}
