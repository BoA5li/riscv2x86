#include "riscv2x86/Report.h"
#include <fstream>
#include <ostream>
#include <sstream>

namespace riscv2x86 {

static const char* catName(Category c) {
    switch (c) {
        case Category::PortableC: return "PortableC";
        case Category::ReplaceableByRule: return "ReplaceableByRule";
        case Category::NeedsAsmTranslation: return "NeedsAsmTranslation";
        case Category::Unsupported: return "Unsupported";
    }
    return "?";
}

static const char* kindName(AsmKind k) {
    switch (k) {
        case AsmKind::InlineBasic: return "InlineBasic";
        case AsmKind::InlineExtended: return "InlineExtended";
        case AsmKind::InlineGoto: return "InlineGoto";
        case AsmKind::FileScope: return "FileScope";
        case AsmKind::DotSFile: return "DotSFile";
    }
    return "?";
}

static std::string escape(const std::string &s) {
    std::string r;
    r.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default: r += c; break;
        }
    }
    return r;
}

static void dumpStringArrayJSON(std::ostream &os,
                                const char *key,
                                const std::vector<std::string> &arr,
                                unsigned indentSpaces = 6) {
    std::string indent(indentSpaces, ' ');
    os << indent << "\"" << key << "\": [";
    for (size_t i = 0; i < arr.size(); ++i) {
        os << "\"" << escape(arr[i]) << "\"";
        if (i + 1 < arr.size()) os << ",";
    }
    os << "]";
}

void ClassificationReport::dumpText(std::ostream &os) const {
    os << "=== riscv2x86 classification report ===\n";
    os << "total findings: " << findings.size() << "\n";
    for (const auto &f : findings) {
        os << "- [" << catName(f.category) << "] "
           << f.fileName << ":" << f.line << ":" << f.column
           << " " << f.description << "\n";

        if (!f.subjectKind.empty())
            os << "    subjectKind: " << f.subjectKind << "\n";

        if (!f.symbolName.empty())
            os << "    symbolName: " << f.symbolName << "\n";

        if (f.fromMacroExpansion)
            os << "    macro: " << (f.macroName.empty() ? "<unknown>" : f.macroName) << "\n";

        if (f.hasRewriteRange) {
            os << "    rewriteRange: [" << f.rewriteBeginOffset
               << ", " << f.rewriteEndOffset << ")\n";
        }

        if (!f.rawSourceText.empty())
            os << "    src: " << f.rawSourceText << "\n";

        if (!f.arguments.empty()) {
            os << "    args:";
            for (const auto &a : f.arguments) os << " [" << a << "]";
            os << "\n";
        }

        if (!f.ruleName.empty())
            os << "    rule: " << f.ruleName << "\n";

        if (!f.suggestedReplacement.empty())
            os << "    => " << f.suggestedReplacement << "\n";

        if (f.fragment.has_value() && !f.fragment->rawAsmText.empty())
            os << "    asm: " << f.fragment->rawAsmText << "\n";
    }
}

void ClassificationReport::dumpJSON(const std::string &path) const {
    std::ofstream os(path.c_str(), std::ios::out | std::ios::trunc);
    if (!os) return;

    os << "{\n";
    os << "  \"findings\": [\n";

    for (size_t i = 0; i < findings.size(); ++i) {
        const auto &f = findings[i];

        os << "    {\n";
        os << "      \"category\": \"" << catName(f.category) << "\",\n";
        os << "      \"file\": \"" << escape(f.fileName) << "\",\n";
        os << "      \"fileName\": \"" << escape(f.fileName) << "\",\n";
        os << "      \"line\": " << f.line << ",\n";
        os << "      \"column\": " << f.column << ",\n";
        os << "      \"description\": \"" << escape(f.description) << "\",\n";

        os << "      \"rule\": \"" << escape(f.ruleName) << "\",\n";
        os << "      \"ruleName\": \"" << escape(f.ruleName) << "\",\n";

        os << "      \"replacement\": \"" << escape(f.suggestedReplacement) << "\",\n";
        os << "      \"suggestedReplacement\": \"" << escape(f.suggestedReplacement) << "\",\n";

        os << "      \"subjectKind\": \"" << escape(f.subjectKind) << "\",\n";
        os << "      \"symbolName\": \"" << escape(f.symbolName) << "\",\n";

        os << "      \"hasRewriteRange\": " << (f.hasRewriteRange ? "true" : "false") << ",\n";
        os << "      \"rewriteBeginOffset\": " << f.rewriteBeginOffset << ",\n";
        os << "      \"rewriteEndOffset\": " << f.rewriteEndOffset << ",\n";
        os << "      \"rawSourceText\": \"" << escape(f.rawSourceText) << "\",\n";

        os << "      \"fromMacroExpansion\": " << (f.fromMacroExpansion ? "true" : "false") << ",\n";
        os << "      \"macroName\": \"" << escape(f.macroName) << "\",\n";
        if (f.approvalArtifact.present) {
            const auto &a = f.approvalArtifact;
            os << "      \"approvalArtifact\": {\"artifactVersion\":\"" << escape(a.artifactVersion) << "\",\"proofStatus\":\"" << escape(a.proofStatus) << "\",\"sourceFragmentId\":\"" << escape(a.sourceFragmentId) << "\",\"sourceModelId\":\"" << escape(a.sourceModelId) << "\",\"preservationDecisionId\":\"" << escape(a.preservationDecisionId) << "\",\"planId\":\"" << escape(a.planId) << "\",\"constraintsId\":\"" << escape(a.constraintsId) << "\",\"targetEnvironmentId\":\"" << escape(a.targetEnvironmentId) << "\",\"targetCatalogVersion\":\"" << escape(a.targetCatalogVersion) << "\",\"selectionPolicyId\":\"" << escape(a.selectionPolicyId) << "\",\"selectionPolicyVersion\":\"" << escape(a.selectionPolicyVersion) << "\",\"selectionTier\":\"" << escape(a.selectionTier) << "\",\"rendererId\":\"" << escape(a.rendererId) << "\",\"rendererVersion\":\"" << escape(a.rendererVersion) << "\",\"replacementKind\":\"" << escape(a.replacementKind) << "\",\"replacementDigest\":\"" << escape(a.replacementDigest) << "\",\"sourceSliceDigest\":\"" << escape(a.sourceSliceDigest) << "\"},\n";
        }

        dumpStringArrayJSON(os, "arguments", f.arguments, 6);

        if (f.fragment.has_value()) {
            const auto &g = *f.fragment;

            os << ",\n";
            os << "      \"fragment\": {\n";
            os << "        \"kind\": \"" << kindName(g.kind) << "\",\n";
            os << "        \"rawAsmText\": \"" << escape(g.rawAsmText) << "\",\n";
            os << "        \"asmText\": \"" << escape(g.rawAsmText) << "\",\n";
            os << "        \"isVolatile\": " << (g.isVolatile ? "true" : "false") << ",\n";
            os << "        \"fileName\": \"" << escape(g.fileName) << "\",\n";
            os << "        \"line\": " << g.line << ",\n";
            os << "        \"column\": " << g.column << ",\n";
            os << "        \"beginOffset\": " << g.beginOffset << ",\n";
            os << "        \"endOffset\": " << g.endOffset << ",\n";
            os << "        \"enclosingFunction\": \"" << escape(g.enclosingFunction) << "\",\n";
            os << "        \"id\": \"" << escape(g.id) << "\",\n";

            auto dumpOps = [&](const std::vector<AsmOperand>& v, const char* key) {
                os << "        \"" << key << "\": [";
                for (size_t j = 0; j < v.size(); ++j) {
                    const auto &o = v[j];
                    os << "{\"constraint\":\"" << escape(o.constraint)
                       << "\",\"exprText\":\"" << escape(o.exprText)
                       << "\",\"symbolicName\":\"" << escape(o.symbolicName)
                       << "\",\"isOutput\":" << (o.isOutput ? "true" : "false")
                       << ",\"isTied\":" << (o.isTied ? "true" : "false")
                       << ",\"isEarlyClobber\":" << (o.isEarlyClobber ? "true" : "false")
                       << "}";
                    if (j + 1 < v.size()) os << ",";
                }
                os << "]";
            };

            dumpOps(g.outputs, "outputs");
            os << ",\n";
            dumpOps(g.inputs, "inputs");
            os << ",\n";

            os << "        \"operandWidthBits\": {";

            size_t widthCount = 0;
            for (const auto &entry : g.operandWidthBits) {
                os << "\"" << entry.first << "\": " << entry.second;

                ++widthCount;
                if (widthCount < g.operandWidthBits.size()) {
                    os << ",";
                }
            }

            os << "},\n";

            os << "        \"clobbers\": [";
            for (size_t j = 0; j < g.clobbers.size(); ++j) {
                os << "\"" << escape(g.clobbers[j]) << "\"";
                if (j + 1 < g.clobbers.size()) os << ",";
            }
            os << "],\n";

            os << "        \"gotoLabels\": [";
            for (size_t j = 0; j < g.gotoLabels.size(); ++j) {
                os << "\"" << escape(g.gotoLabels[j]) << "\"";
                if (j + 1 < g.gotoLabels.size()) os << ",";
            }
            os << "]\n";

            os << "      }";
        }

        os << "\n";
        os << "    }";
        if (i + 1 < findings.size()) os << ",";
        os << "\n";
    }

    os << "  ]\n";
    os << "}\n";
}

} // namespace riscv2x86
