#include "riscv2x86/RuleEngine.h"
#include "riscv2x86/PublicReplacement.h"

namespace riscv2x86 {

extern void registerAtomicRules(RuleEngine &);
extern void registerBuiltinRules(RuleEngine &);

namespace {

bool hasUsableRewriteRange(const Finding &f) {
    if (f.hasRewriteRange && f.rewriteEndOffset > f.rewriteBeginOffset)
        return true;

    // 兼容旧对象
    if (f.rewriteEndOffset > f.rewriteBeginOffset)
        return true;

    if (f.fragment.has_value() && f.fragment->endOffset > f.fragment->beginOffset)
        return true;

    return false;
}

void materializeRewriteRangeFromFragment(Finding &f) {
    if (f.hasRewriteRange && f.rewriteEndOffset > f.rewriteBeginOffset)
        return;

    if (f.rewriteEndOffset > f.rewriteBeginOffset) {
        f.hasRewriteRange = true;
        return;
    }

    if (!f.fragment.has_value())
        return;

    if (f.fragment->endOffset <= f.fragment->beginOffset)
        return;

    f.rewriteBeginOffset = f.fragment->beginOffset;
    f.rewriteEndOffset = f.fragment->endOffset;
    f.hasRewriteRange = true;
}

} // namespace

RuleEngine::RuleEngine() {}

void RuleEngine::addRule(Rule r) {
    rules_.push_back(std::move(r));
}

void RuleEngine::loadBuiltinRules() {
    registerAtomicRules(*this);
    registerBuiltinRules(*this);
}

void RuleEngine::apply(ClassificationReport &report) {
    for (auto &f : report.findings) {
        if (f.category != Category::NeedsAsmTranslation) continue;

        // Phase 1/2 is intentionally AST-builtin-only.  Never classify raw
        // asm text as ReplaceableByRule: doing so bypasses the Phase 4--6
        // machine-semantics/proof path for atomics, barriers and shell state.
        const auto *contract = findPublicReplacementContract(f);
        if (contract == nullptr ||
            contract->disposition != PublicReplacementDisposition::Replace ||
            !publicReplacementContractMatches(*contract, f) ||
            contract->replacement.empty() ||
            contract->rendererRecipeId.empty()) {
            continue;
        }

        if (!hasUsableRewriteRange(f)) continue;
        materializeRewriteRangeFromFragment(f);

        f.suggestedReplacement = contract->replacement;
        f.ruleName = "phase2.public." + contract->semanticContractId;
        f.publicApprovalArtifact = makePublicReplacementApprovalArtifact(
            *contract, f, f.suggestedReplacement
        );
        f.category = Category::ReplaceableByRule;

        // Public contracts are the only direct-replacement route.  Legacy
        // Rule objects are retained as an API shell for source compatibility,
        // but are intentionally not allowed to turn an asm fragment into a
        // rewrite.
    }
}

} // namespace riscv2x86
