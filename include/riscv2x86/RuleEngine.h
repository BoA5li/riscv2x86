#pragma once
#include "Report.h"
#include "AsmFragment.h"
#include <functional>
#include <vector>
#include <string>

namespace riscv2x86 {

// 一条替换规则
struct Rule {
    std::string name;
    std::string description;

    // 旧接口：asm fragment 级规则
    std::function<bool(const AsmFragment&)> matches;
    std::function<std::string(const AsmFragment&)> generate;

    // 新接口：finding 级规则（builtin / macro / future generic)
    std::function<bool(const Finding&)> matchesFinding;
    std::function<std::string(const Finding&)> generateFinding;
};

class RuleEngine {
public:
    RuleEngine();
    void addRule(Rule r);

    // 对每个 NeedsAsmTranslation 的 finding 尝试匹配
    // 命中则把它转为 ReplaceableByRule，并填 suggestedReplacement/ruleName
    void apply(ClassificationReport &report);

    // 内置规则注册
    void loadBuiltinRules();

private:
    std::vector<Rule> rules_;
};

} // namespace riscv2x86