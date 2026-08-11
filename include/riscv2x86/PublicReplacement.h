#pragma once
#include "Report.h"
#include <optional>
#include <string>
#include <vector>

namespace riscv2x86 {

enum class PublicReplacementDisposition { Replace, NeedsSemanticRoute, Unsupported };

// Phase 1/2 contract: source identity and language-level rendering only.
// It must never contain an asm fallback or an inferred target instruction.
struct PublicReplacementContract {
    std::string semanticContractId;
    std::string semanticContractVersion;
    std::string sourceBuiltin;
    std::vector<BuiltinFinding::TypeContract> argumentTypes;
    BuiltinFinding::TypeContract resultType;
    bool resultMustBeRValue = true;
    bool allowMacroExpansion = false;
    std::string targetEnvironmentId;
    std::string requiredCompilerFamily;
    std::string requiredCompilerVersion;
    std::string requiredCompilerCapability;
    std::vector<std::string> requiredHeaders;
    std::vector<std::string> requiredTargetFeatures;
    std::string preservationLevel;
    PublicReplacementDisposition disposition = PublicReplacementDisposition::NeedsSemanticRoute;
    std::string fallbackPolicy;
    std::string rendererRecipeId;
    std::string replacement;
};

const PublicReplacementContract *findPublicReplacementContract(const Finding &finding);
bool publicReplacementContractMatches(const PublicReplacementContract &contract,
                                      const Finding &finding);
PublicReplacementApprovalArtifact makePublicReplacementApprovalArtifact(
    const PublicReplacementContract &contract,
    const Finding &finding,
    const std::string &replacement);

} // namespace riscv2x86
