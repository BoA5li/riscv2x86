#include "riscv2x86/RuleEngine.h"
#include <regex>
#include <string>
#include <cctype>

namespace riscv2x86 {

namespace {

static std::string trimCopy(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

static bool containsConstraintChar(const std::string &constraint, char c) {
    return constraint.find(c) != std::string::npos;
}

static bool hasOnlyMemoryClobber(const AsmFragment &f) {
    for (const auto &c : f.clobbers) {
        if (trimCopy(c) != "memory") return false;
    }
    return true;
}

static bool hasAddressLikeOperand(const AsmFragment &f) {
    for (const auto &op : f.outputs) {
        if (containsConstraintChar(op.constraint, 'A')) return true;
    }
    for (const auto &op : f.inputs) {
        if (containsConstraintChar(op.constraint, 'A')) return true;
    }
    return false;
}

static bool matchAmoAdd(const AsmFragment &f) {
    if (f.kind != AsmKind::InlineExtended) return false;
    if (f.outputs.empty()) return false;
    if (f.inputs.empty()) return false;
    if (f.outputs[0].exprText.empty()) return false;
    if (!containsConstraintChar(f.outputs[0].constraint, 'r')) return false;
    if (!hasAddressLikeOperand(f)) return false;
    if (!hasOnlyMemoryClobber(f)) return false;

    for (const auto &op : f.outputs) {
        if (op.isEarlyClobber) return false;
    }
    for (const auto &op : f.inputs) {
        if (op.isTied) return false;
    }

    std::regex re(R"(\bamoadd\.(w|d)(?:\.(aq|rl|aqrl))?\b)", std::regex::icase);
    return std::regex_search(f.rawAsmText, re);
}

static std::string amoOrderFor(const std::string &rawAsmText) {
    std::smatch m;
    std::regex re(R"(\bamoadd\.(w|d)(?:\.(aq|rl|aqrl))?\b)", std::regex::icase);
    if (!std::regex_search(rawAsmText, m, re)) {
        return "";
    }

    std::string suffix = m[2].matched ? m[2].str() : "";
    if (suffix == "aq" || suffix == "AQ") return "__ATOMIC_ACQUIRE";
    if (suffix == "rl" || suffix == "RL") return "__ATOMIC_RELEASE";
    if (suffix == "aqrl" || suffix == "AQRL") return "__ATOMIC_SEQ_CST";
    return "__ATOMIC_RELAXED";
}

static std::string genAmoAdd(const AsmFragment &f) {
    std::string oldLv = f.outputs.size() > 0 ? f.outputs[0].exprText : "";
    if (oldLv.empty()) return "";

    std::string addrExpr;
    for (size_t i = 1; i < f.outputs.size(); ++i) {
        if (containsConstraintChar(f.outputs[i].constraint, 'A') &&
            !f.outputs[i].exprText.empty()) {
            addrExpr = "&(" + f.outputs[i].exprText + ")";
            break;
        }
    }
    if (addrExpr.empty()) {
        for (const auto &in : f.inputs) {
            if (containsConstraintChar(in.constraint, 'A') &&
                !in.exprText.empty()) {
                addrExpr = "&(" + in.exprText + ")";
                break;
            }
        }
    }

    if (addrExpr.empty()) return "";

    std::string val = !f.inputs.empty() ? f.inputs.back().exprText : "";
    if (val.empty()) return "";

    std::string order = amoOrderFor(f.rawAsmText);
    if (order.empty()) return "";

    return oldLv + " = __atomic_fetch_add(" + addrExpr + ", " + val +
           ", " + order + ");";
}

static bool matchFence(const AsmFragment &f) {
    if (f.kind == AsmKind::InlineGoto) return false;
    if (!f.outputs.empty() || !f.inputs.empty()) return false;
    if (!hasOnlyMemoryClobber(f) && !f.clobbers.empty()) return false;

    std::string s = trimCopy(f.rawAsmText);
    std::regex re(R"(^fence$)", std::regex::icase);
    return std::regex_match(s, re);
}

static std::string genFence(const AsmFragment &) {
    return "__atomic_thread_fence(__ATOMIC_SEQ_CST);";
}

} // namespace

void registerAtomicRules(RuleEngine &eng) {
    eng.addRule({
        "atomic.amoadd",
        "RISC-V amoadd.{w,d}[.aq|.rl|.aqrl] -> __atomic_fetch_add",
        matchAmoAdd, genAmoAdd, {}, {}
    });
    eng.addRule({
        "atomic.fence",
        "RISC-V bare fence -> __atomic_thread_fence(seq_cst)",
        matchFence, genFence, {}, {}
    });
}

} // namespace riscv2x86