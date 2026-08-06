#include "riscv2x86/RuleEngine.h"
#include <algorithm>
#include <cctype>
#include <regex>
#include <string>

namespace riscv2x86 {

namespace {

static std::string trimCopy(const std::string &s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

static std::string normalizeSpacesLower(const std::string &s) {
    std::string out;
    out.reserve(s.size());

    bool prevSpace = false;
    for (unsigned char ch : s) {
        if (std::isspace(ch)) {
            if (!prevSpace) {
                out.push_back(' ');
                prevSpace = true;
            }
        } else {
            out.push_back(static_cast<char>(std::tolower(ch)));
            prevSpace = false;
        }
    }

    return trimCopy(out);
}

static bool hasRewriteRange(const Finding &f) {
    if (f.hasRewriteRange && f.rewriteEndOffset > f.rewriteBeginOffset)
        return true;
    if (f.rewriteEndOffset > f.rewriteBeginOffset)
        return true;
    if (f.fragment.has_value() && f.fragment->endOffset > f.fragment->beginOffset)
        return true;
    return false;
}

static bool isWritableRegisterOutputConstraint(const std::string &constraint) {
    std::string s = normalizeSpacesLower(constraint);
    return s.find('=') != std::string::npos && s.find('r') != std::string::npos;
}

static bool matchAsmRdcycle(const AsmFragment &f) {
    if (f.kind != AsmKind::InlineExtended) return false;
    if (f.outputs.size() != 1) return false;
    if (!f.inputs.empty()) return false;
    if (!f.gotoLabels.empty()) return false;
    if (!f.clobbers.empty()) return false;
    if (f.outputs[0].exprText.empty()) return false;
    if (!isWritableRegisterOutputConstraint(f.outputs[0].constraint)) return false;

    static const std::regex re(
        R"(^rdcycle\s+(%0|%\[[a-z_][a-z0-9_]*\])$)"
    );

    return std::regex_match(normalizeSpacesLower(f.rawAsmText), re);
}

static std::string genAsmRdcycle(const AsmFragment &f) {
    const std::string &lv = f.outputs[0].exprText;
    if (lv.empty()) return "";
    return lv + " = __builtin_readcyclecounter();";
}

// 说明：这条 finding 级规则同时覆盖：
// 1) 直接 builtin 调用
// 2) 宏展开出来的 builtin 调用
// 前提是分类阶段已经把 rewrite range 对准了“最终应替换的源码区间”
static bool matchBuiltinRdcycleCall(const Finding &f) {
    if (!f.builtin.has_value()) return false;
    if (!hasRewriteRange(f)) return false;

    const std::string &name = f.builtin->calleeName;
    return name == "__builtin_riscv_rdcycle" || name == "__riscv_rdcycle";
}

static std::string genBuiltinRdcycleCall(const Finding &) {
    return "__builtin_readcyclecounter()";
}

static bool matchNop(const AsmFragment &f) {
    if (f.kind == AsmKind::FileScope || f.kind == AsmKind::InlineGoto) return false;
    if (!f.outputs.empty()) return false;
    if (!f.inputs.empty()) return false;
    if (!f.gotoLabels.empty()) return false;
    if (!f.clobbers.empty()) return false;

    return normalizeSpacesLower(f.rawAsmText) == "nop";
}

static std::string genNop(const AsmFragment &) {
    // 按你的要求，不强行消灭 asm；等价同语义 asm 也是可接受结果
    return "__asm__ __volatile__(\"nop\");";
}

} // namespace

void registerBuiltinRules(RuleEngine &eng) {
    eng.addRule({
        "builtin.rdcycle.asm",
        "RISC-V asm rdcycle -> __builtin_readcyclecounter assignment",
        matchAsmRdcycle,
        genAsmRdcycle,
        {},
        {}
    });

    eng.addRule({
        "builtin.rdcycle.call",
        "RISC-V builtin rdcycle() -> __builtin_readcyclecounter()",
        {},
        {},
        matchBuiltinRdcycleCall,
        genBuiltinRdcycleCall
    });

    eng.addRule({
        "builtin.nop",
        "Keep nop as equivalent asm",
        matchNop,
        genNop,
        {},
        {}
    });
}

} // namespace riscv2x86