#include "riscv2x86/PublicReplacement.h"

#include <cstdint>
#include <iomanip>
#include <sstream>

namespace riscv2x86 {
namespace {

static std::string digest(const std::string &value) {
    std::uint64_t state = 14695981039346656037ULL;
    for (unsigned char byte : value)
        state = (state ^ byte) * 1099511628211ULL;
    std::ostringstream out;
    out << "fnv1a64:" << std::hex << std::nouppercase
        << std::setw(16) << std::setfill('0') << state;
    return out.str();
}

} // namespace

const PublicReplacementContract *findPublicReplacementContract(const Finding &finding) {
    // The registry is intentionally conservative.  These entries make the
    // fallback decision explicit, but neither counter has a portable x86
    // public equivalent with the required timing/microarchitecture contract.
    // New Replace entries must be reviewed together with their target
    // capability, recipe, artifact validation and positive/negative tests.
    static const PublicReplacementContract contracts[] = {
        {
            "public.riscv.rdcycle.needs-route", "v1",
            "__builtin_riscv_rdcycle", {}, "unsigned long",
            true, false, "", "", "", "",
            {}, {}, "not_preserved",
            PublicReplacementDisposition::NeedsSemanticRoute,
            "needs_route", "", ""
        },
        {
            "public.riscv.rdcycle.needs-route", "v1",
            "__riscv_rdcycle", {}, "unsigned long",
            true, false, "", "", "", "",
            {}, {}, "not_preserved",
            PublicReplacementDisposition::NeedsSemanticRoute,
            "needs_route", "", ""
        },
    };
    if (!finding.builtin.has_value()) return nullptr;
    for (const auto &contract : contracts) {
        if (contract.sourceBuiltin == finding.builtin->calleeName)
            return &contract;
    }
    return nullptr;
}

bool publicReplacementContractMatches(const PublicReplacementContract &contract,
                                      const Finding &finding) {
    const auto &builtin = finding.builtin;
    if (!builtin.has_value() || builtin->calleeName != contract.sourceBuiltin)
        return false;
    if (finding.fromMacroExpansion && !contract.allowMacroExpansion)
        return false;
    if (builtin->argumentTypeIds != contract.argumentTypeIds)
        return false;
    if (builtin->resultTypeId != contract.resultTypeId)
        return false;
    if (contract.resultMustBeRValue && builtin->resultIsLValue)
        return false;
    return true;
}

PublicReplacementApprovalArtifact makePublicReplacementApprovalArtifact(
    const PublicReplacementContract &contract,
    const Finding &finding,
    const std::string &replacement) {
    PublicReplacementApprovalArtifact artifact;
    artifact.present = true;
    // Target capability/environment validation happens in the Python
    // launcher before this is promoted to approved.  A C++ frontend report
    // therefore cannot be applied directly while its public artifact is
    // pending.
    artifact.artifactVersion = "phase2-public-approval-v1";
    artifact.approvalStatus = "pending_target_validation";
    artifact.semanticContractId = contract.semanticContractId;
    artifact.semanticContractVersion = contract.semanticContractVersion;
    artifact.sourceBuiltin = contract.sourceBuiltin;
    artifact.targetEnvironmentId = contract.targetEnvironmentId;
    artifact.compilerCapability = contract.requiredCompilerCapability;
    artifact.rendererRecipeId = contract.rendererRecipeId;
    artifact.preservationLevel = contract.preservationLevel;
    artifact.fallbackPolicy = contract.fallbackPolicy;
    artifact.replacementDigest = digest(replacement);
    artifact.sourceSliceDigest = digest(finding.rawSourceText);
    return artifact;
}

} // namespace riscv2x86
