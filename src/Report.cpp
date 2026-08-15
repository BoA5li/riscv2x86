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
        case Category::NeedsRoute: return "NeedsRoute";
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

static void dumpTypeContractJSON(std::ostream &os, const BuiltinFinding::TypeContract &t) {
    os << "{\"canonicalType\":\"" << escape(t.canonicalType)
       << "\",\"widthBits\":" << t.widthBits
       << ",\"isSigned\":" << (t.isSigned ? "true" : "false")
       << ",\"isPointer\":" << (t.isPointer ? "true" : "false")
       << ",\"alignmentBytes\":" << t.alignmentBytes
       << ",\"pointeeCanonicalType\":\"" << escape(t.pointeeCanonicalType)
       << "\",\"qualifiers\":\"" << escape(t.qualifiers) << "\"}";
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
        if (f.publicApprovalArtifact.present) {
            const auto &a = f.publicApprovalArtifact;
            os << "      \"publicApprovalArtifact\": {\"artifactVersion\":\"" << escape(a.artifactVersion)
               << "\",\"approvalStatus\":\"" << escape(a.approvalStatus)
               << "\",\"semanticContractId\":\"" << escape(a.semanticContractId)
               << "\",\"semanticContractVersion\":\"" << escape(a.semanticContractVersion)
               << "\",\"sourceBuiltin\":\"" << escape(a.sourceBuiltin)
               << "\",\"targetEnvironmentId\":\"" << escape(a.targetEnvironmentId)
               << "\",\"compilerCapability\":\"" << escape(a.compilerCapability)
               << "\",\"compilerFamily\":\"" << escape(a.compilerFamily)
               << "\",\"compilerVersion\":\"" << escape(a.compilerVersion)
               << "\",\"rendererRecipeId\":\"" << escape(a.rendererRecipeId)
               << "\",\"preservationLevel\":\"" << escape(a.preservationLevel)
               << "\",\"fallbackPolicy\":\"" << escape(a.fallbackPolicy)
               << "\",\"replacementDigest\":\"" << escape(a.replacementDigest)
               << "\",\"sourceSliceDigest\":\"" << escape(a.sourceSliceDigest)
               << "\",\"requiredHeaders\":[";
            for (size_t j = 0; j < a.requiredHeaders.size(); ++j) {
                os << "\"" << escape(a.requiredHeaders[j]) << "\"";
                if (j + 1 < a.requiredHeaders.size()) os << ",";
            }
            os << "],\"requiredTargetFeatures\":[";
            for (size_t j = 0; j < a.requiredTargetFeatures.size(); ++j) {
                os << "\"" << escape(a.requiredTargetFeatures[j]) << "\"";
                if (j + 1 < a.requiredTargetFeatures.size()) os << ",";
            }
            os << "]},\n";
        }
        if (f.approvalArtifact.present) {
            const auto &a = f.approvalArtifact;
            os << "      \"approvalArtifact\": {\"artifactVersion\":\"" << escape(a.artifactVersion) << "\",\"proofStatus\":\"" << escape(a.proofStatus) << "\",\"sourceFragmentId\":\"" << escape(a.sourceFragmentId) << "\",\"sourceModelId\":\"" << escape(a.sourceModelId) << "\",\"preservationDecisionId\":\"" << escape(a.preservationDecisionId) << "\",\"planId\":\"" << escape(a.planId) << "\",\"constraintsId\":\"" << escape(a.constraintsId) << "\",\"targetEnvironmentId\":\"" << escape(a.targetEnvironmentId) << "\",\"targetCatalogVersion\":\"" << escape(a.targetCatalogVersion) << "\",\"selectionPolicyId\":\"" << escape(a.selectionPolicyId) << "\",\"selectionPolicyVersion\":\"" << escape(a.selectionPolicyVersion) << "\",\"selectionTier\":\"" << escape(a.selectionTier) << "\",\"rendererId\":\"" << escape(a.rendererId) << "\",\"rendererVersion\":\"" << escape(a.rendererVersion) << "\",\"replacementKind\":\"" << escape(a.replacementKind) << "\",\"replacementDigest\":\"" << escape(a.replacementDigest) << "\",\"sourceSliceDigest\":\"" << escape(a.sourceSliceDigest) << "\",\"helperRuntimeContractId\":\"" << escape(a.helperRuntimeContractId) << "\",\"helperSemanticVersion\":\"" << escape(a.helperSemanticVersion) << "\",\"helperRequiredHeader\":\"" << escape(a.helperRequiredHeader) << "\",\"helperRuntimeLibrary\":\"" << escape(a.helperRuntimeLibrary) << "\",\"helperRuntimeManifestVersion\":\"" << escape(a.helperRuntimeManifestVersion) << "\",\"functionalFallbackEnabled\":" << (a.functionalFallbackEnabled ? "true" : "false") << ",\"preservationMode\":\"" << escape(a.preservationMode) << "\",\"sourceSemanticContractId\":\"" << escape(a.sourceSemanticContractId) << "\",\"targetSemanticContractId\":\"" << escape(a.targetSemanticContractId) << "\"},\n";
        }

        dumpStringArrayJSON(os, "arguments", f.arguments, 6);
        if (f.builtin.has_value()) {
            const auto &b = *f.builtin;
            os << ",\n      \"builtin\": {\"calleeName\":\"" << escape(b.calleeName)
               << "\",\"args\":[";
            for (size_t j = 0; j < b.args.size(); ++j) {
                os << "\"" << escape(b.args[j]) << "\"";
                if (j + 1 < b.args.size()) os << ",";
            }
            os << "],\"argumentTypeIds\":[";
            for (size_t j = 0; j < b.argumentTypeIds.size(); ++j) {
                os << "\"" << escape(b.argumentTypeIds[j]) << "\"";
                if (j + 1 < b.argumentTypeIds.size()) os << ",";
            }
            os << "],\"resultTypeId\":\"" << escape(b.resultTypeId)
               << "\",\"resultIsLValue\":" << (b.resultIsLValue ? "true" : "false")
               << ",\"argumentTypes\":[";
            for (size_t j = 0; j < b.argumentTypes.size(); ++j) {
                dumpTypeContractJSON(os, b.argumentTypes[j]);
                if (j + 1 < b.argumentTypes.size()) os << ",";
            }
            os << "],\"resultType\":";
            dumpTypeContractJSON(os, b.resultType);
            os << "}";
        }

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
            os << "],\n";
            os << "        \"gotoEdges\": [";
            for (size_t j = 0; j < g.gotoEdges.size(); ++j) {
                const auto &edge = g.gotoEdges[j];
                os << "{\"asmTarget\":\"" << escape(edge.asmTarget)
                   << "\",\"cLabel\":\"" << escape(edge.cLabel)
                   << "\",\"exitCode\":" << edge.exitCode
                   << ",\"targetContinuationId\":\""
                   << escape(edge.targetContinuationId) << "\"}";
                if (j + 1 < g.gotoEdges.size()) os << ",";
            }
            os << "],\n";
            os << "        \"asmGotoFallthroughContinuationId\":\""
               << escape(g.asmGotoFallthroughContinuationId) << "\",\n";
            os << "        \"asmGotoConditionKind\":\"" << escape(g.asmGotoConditionKind) << "\",\n";
            os << "        \"asmGotoConditionOperandIndex\":" << g.asmGotoConditionOperandIndex << ",\n";
            os << "        \"asmGotoSuccessorContinuationIds\": [";
            for (size_t j = 0; j < g.asmGotoSuccessorContinuationIds.size(); ++j) {
                os << "\"" << escape(g.asmGotoSuccessorContinuationIds[j]) << "\"";
                if (j + 1 < g.asmGotoSuccessorContinuationIds.size()) os << ",";
            }
            os << "],\n";
            os << "        \"asmGotoControlFlowComplete\":"
               << (g.asmGotoControlFlowComplete ? "true" : "false") << "\n";

            os << "      }";
        }

        os << "\n";
        os << "    }";
        if (i + 1 < findings.size()) os << ",";
        os << "\n";
    }

    os << "  ],\n  \"functionFrontendFacts\": [\n";
    for (size_t i = 0; i < functionFrontendFacts.size(); ++i) {
        const auto &ff = functionFrontendFacts[i];
        os << "    {\"functionId\":\"" << escape(ff.functionId)
           << "\",\"cAstFunctionBindingId\":\"" << escape(ff.cAstFunctionBindingId)
           << "\",\"sourceFile\":\"" << escape(ff.fileName)
           << "\",\"definitionRange\":{\"start\":" << ff.definitionBeginOffset << ",\"end\":" << ff.definitionEndOffset
           << "},\"bodyRange\":{\"start\":" << ff.bodyBeginOffset << ",\"end\":" << ff.bodyEndOffset
           << "},\"hasVlaOrCleanupSensitiveScope\":" << (ff.hasVLAOrCleanupSensitiveScope ? "true" : "false")
           << ",\"macroSensitiveScope\":" << (ff.macroSensitiveScope ? "true" : "false")
           << ",\"regions\":[{\"regionId\":\"c-body\",\"kind\":\"c_body\",\"start\":" << ff.bodyBeginOffset << ",\"end\":" << ff.bodyEndOffset << ",\"complete\":" << (ff.complete ? "true" : "false") << "}]"
           << ",\"fragmentIds\":[";
        bool first = true;
        for (const auto &finding : findings) if (finding.fragment.has_value()) { const auto &g=*finding.fragment; if (g.fileName == ff.fileName && g.beginOffset >= ff.bodyBeginOffset && g.endOffset <= ff.bodyEndOffset) { if (!first) os << ","; os << "\"" << escape(g.id) << "\""; first=false; } }
        os << "],\"missingFactCodes\":[";
        for (size_t j=0;j<ff.missingFactCodes.size();++j) { os << "\"" << escape(ff.missingFactCodes[j]) << "\""; if(j+1<ff.missingFactCodes.size()) os << ","; }
        os << "],\"complete\":" << (ff.complete ? "true" : "false") << ",\"provenance\":\"clang-frontend.v1\"}";
        if (i + 1 < functionFrontendFacts.size()) os << ",";
        os << "\n";
    }
    os << "  ]\n";
    os << "}\n";
}

} // namespace riscv2x86
