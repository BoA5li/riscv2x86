#pragma once
#include "Report.h"
#include <optional>
#include <string>
#include <vector>

namespace riscv2x86 {

enum class PublicReplacementDisposition { Replace, NeedsSemanticRoute };

// Phase 1/2 contract: source identity and language-level rendering only.
// It must never contain an asm fallback or an inferred target instruction.
struct PublicReplacementContract {
    std::string sourceBuiltin;
    unsigned argumentCount = 0;
    std::string requiredCompilerCapability;
    std::vector<std::string> requiredHeaders;
    std::string preservationLevel;
    PublicReplacementDisposition disposition = PublicReplacementDisposition::NeedsSemanticRoute;
    std::string replacement;
};

const PublicReplacementContract *findPublicReplacementContract(const Finding &finding);

} // namespace riscv2x86
