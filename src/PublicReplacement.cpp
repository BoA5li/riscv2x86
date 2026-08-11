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

static BuiltinFinding::TypeContract unsignedInteger(unsigned width) {
    BuiltinFinding::TypeContract t;
    t.widthBits = width;
    t.isSigned = false;
    t.alignmentBytes = width / 8;
    return t;
}

static bool typeMatches(const BuiltinFinding::TypeContract &required,
                        const BuiltinFinding::TypeContract &actual) {
    return required.widthBits == actual.widthBits &&
           required.isSigned == actual.isSigned &&
           required.isPointer == actual.isPointer &&
           required.alignmentBytes == actual.alignmentBytes &&
           required.pointeeCanonicalType == actual.pointeeCanonicalType &&
           required.qualifiers == actual.qualifiers &&
           (required.canonicalType.empty() || required.canonicalType == actual.canonicalType);
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
            "__builtin_riscv_rdcycle", {}, unsignedInteger(sizeof(unsigned long) * 8),
            true, false, "", "", "", "",
            {}, {}, "not_preserved",
            PublicReplacementDisposition::NeedsSemanticRoute,
            "needs_route", "", ""
        },
        {
            "public.riscv.rdcycle.needs-route", "v1",
            "__riscv_rdcycle", {}, unsignedInteger(sizeof(unsigned long) * 8),
            true, false, "", "", "", "",
            {}, {}, "not_preserved",
            PublicReplacementDisposition::NeedsSemanticRoute,
            "needs_route", "", ""
        },
        {
            "public.riscv.rev8.u32", "v1",
            "__builtin_riscv_rev8_32", {unsignedInteger(32)}, unsignedInteger(32),
            true, false, "phase2-public:x86_64:sysv_amd64:gnu_att", "gnu", "10+",
            "c_builtin:bswap", {}, {}, "architecture_equivalent",
            PublicReplacementDisposition::Replace, "needs_route",
            "c-builtin-bswap32-v1", "__builtin_bswap32(%0)"
        },
        {
            "public.riscv.rev8.u64", "v1",
            "__builtin_riscv_rev8_64", {unsignedInteger(64)}, unsignedInteger(64),
            true, false, "phase2-public:x86_64:sysv_amd64:gnu_att", "gnu", "10+",
            "c_builtin:bswap", {}, {}, "architecture_equivalent",
            PublicReplacementDisposition::Replace, "needs_route",
            "c-builtin-bswap64-v1", "__builtin_bswap64(%0)"
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
    if (builtin->argumentTypes.size() != contract.argumentTypes.size())
        return false;
    for (size_t i = 0; i < contract.argumentTypes.size(); ++i)
        if (!typeMatches(contract.argumentTypes[i], builtin->argumentTypes[i])) return false;
    if (!typeMatches(contract.resultType, builtin->resultType))
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
    artifact.compilerFamily = contract.requiredCompilerFamily;
    artifact.compilerVersion = contract.requiredCompilerVersion;
    artifact.requiredHeaders = contract.requiredHeaders;
    artifact.requiredTargetFeatures = contract.requiredTargetFeatures;
    artifact.rendererRecipeId = contract.rendererRecipeId;
    artifact.preservationLevel = contract.preservationLevel;
    artifact.fallbackPolicy = contract.fallbackPolicy;
    artifact.replacementDigest = digest(replacement);
    artifact.sourceSliceDigest = digest(finding.rawSourceText);
    return artifact;
}

} // namespace riscv2x86
