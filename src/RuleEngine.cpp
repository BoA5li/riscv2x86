#include "riscv2x86/RuleEngine.h"

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

        for (const auto &r : rules_) {
            bool matched = false;
            std::string replacement;

            // 优先 finding 级规则：builtin / macro-origin builtin / 未来 macro
            if (r.matchesFinding && r.generateFinding) {
                if (r.matchesFinding(f)) {
                    replacement = r.generateFinding(f);
                    matched = !replacement.empty();
                }
            } else if (f.fragment.has_value() && r.matches && r.generate) {
                if (r.matches(*f.fragment)) {
                    replacement = r.generate(*f.fragment);
                    matched = !replacement.empty();
                }
            }

            if (!matched) continue;

            // 命中了规则，但没有稳定 rewrite target，则不能标记为可回写
            if (!hasUsableRewriteRange(f)) {
                continue;
            }

            materializeRewriteRangeFromFragment(f);

            f.suggestedReplacement = std::move(replacement);
            f.ruleName = r.name;
            f.category = Category::ReplaceableByRule;
            break;
        }
    }
}

} // namespace riscv2x86