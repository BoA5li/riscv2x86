#pragma once
#include "AsmFragment.h"
#include <optional>
#include <string>
#include <vector>
#include <iosfwd>

namespace riscv2x86 {

// 分类类别
enum class Category {
    PortableC,            // 纯 C，不动
    ReplaceableByRule,    // 可用公开等价替换
    NeedsAsmTranslation,  // 需要走汇编翻译链路
    NeedsRoute,           // 已知需要专用 runtime / semantic route
    Unsupported           // 暂不支持（CSR / privileged / RVV 等）
};

struct BuiltinFinding {
    std::string calleeName;
    std::vector<std::string> args;
    // Canonical AST type identities.  These are deliberately collected by
    // the frontend instead of being reconstructed from argument text later.
    std::vector<std::string> argumentTypeIds;
    std::string resultTypeId;
    bool resultIsLValue = false;
    // Canonical spelling is diagnostic/audit data; matching uses this
    // semantic shape instead of a compiler-specific type string alone.
    struct TypeContract {
        std::string canonicalType;
        unsigned widthBits = 0;
        bool isSigned = false;
        bool isPointer = false;
        unsigned alignmentBytes = 0;
        std::string pointeeCanonicalType;
        std::string qualifiers;
    };
    std::vector<TypeContract> argumentTypes;
    TypeContract resultType;
};

// Approval for a Phase-1/2 public interface replacement.  This is separate
// from a Phase-6 semantic-proof artifact: it records the versioned language
// contract which was checked before an AST builtin call was made replaceable.
struct PublicReplacementApprovalArtifact {
    bool present = false;
    std::string artifactVersion;
    std::string approvalStatus;
    std::string semanticContractId;
    std::string semanticContractVersion;
    std::string sourceBuiltin;
    std::string targetEnvironmentId;
    std::string compilerCapability;
    std::string compilerFamily;
    std::string compilerVersion;
    std::vector<std::string> requiredHeaders;
    std::vector<std::string> requiredTargetFeatures;
    std::string rendererRecipeId;
    std::string preservationLevel;
    std::string fallbackPolicy;
    std::string replacementDigest;
    std::string sourceSliceDigest;
};

struct TranslationApprovalArtifact {
    bool present = false;
    std::string artifactVersion, proofStatus, sourceFragmentId, sourceModelId;
    std::string preservationDecisionId, planId, constraintsId, targetEnvironmentId;
    std::string targetCatalogVersion, selectionPolicyId, selectionPolicyVersion;
    std::string selectionTier, rendererId, rendererVersion, replacementKind;
    std::string replacementDigest, sourceSliceDigest;
};

struct Finding {
    Category category = Category::NeedsAsmTranslation;
    std::string description;
    std::string fileName;
    unsigned line = 0;
    unsigned column = 0;

    std::optional<AsmFragment> fragment;     // 如果是 asm 类
     std::optional<BuiltinFinding> builtin;
    std::string suggestedReplacement;        // 如果可替换，建议替换文本
    std::string ruleName;                    // 命中的规则名

    // -------- Phase 2 通用改写元数据（新增） --------
    // "AsmFragment" | "BuiltinCall" | "MacroCall" | ""
    std::string subjectKind;

    // builtin 名称 / 宏名 / 其他符号
    std::string symbolName;

    // builtin 或宏调用参数文本
    std::vector<std::string> arguments;

    // 通用 rewrite 区间（优先于 fragment.begin/end 使用）
    bool hasRewriteRange = false;
    unsigned rewriteBeginOffset = 0;
    unsigned rewriteEndOffset = 0;

    // rewrite 区间对应的原始源码
    std::string rawSourceText;

    // 是否来自宏展开
    bool fromMacroExpansion = false;
    std::string macroName;
    PublicReplacementApprovalArtifact publicApprovalArtifact;
    TranslationApprovalArtifact approvalArtifact;
};

struct ClassificationReport {
    std::vector<Finding> findings;
    void dumpJSON(const std::string &path) const;
    void dumpText(std::ostream &os) const;
};

bool loadReportJSON(const std::string &path, ClassificationReport &out);

} // namespace riscv2x86
