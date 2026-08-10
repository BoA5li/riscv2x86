#include "riscv2x86/PublicReplacement.h"

namespace riscv2x86 {

const PublicReplacementContract *findPublicReplacementContract(const Finding &finding) {
    // A registry entry is intentionally not an automatic replacement unless
    // it has a documented public target contract.  rdcycle is a counter with
    // ISA/CPU-specific meaning, so mapping it to an x86 counter is unsafe.
    static const PublicReplacementContract contracts[] = {
        {"__builtin_riscv_rdcycle", 0, "", {}, "not_preserved", PublicReplacementDisposition::NeedsSemanticRoute, ""},
        {"__riscv_rdcycle", 0, "", {}, "not_preserved", PublicReplacementDisposition::NeedsSemanticRoute, ""},
    };
    if (!finding.builtin.has_value()) return nullptr;
    for (const auto &contract : contracts) {
        if (contract.sourceBuiltin == finding.builtin->calleeName &&
            contract.argumentCount == finding.builtin->args.size()) return &contract;
    }
    return nullptr;
}

} // namespace riscv2x86
