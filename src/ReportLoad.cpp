#include "riscv2x86/Report.h"
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <string>

namespace riscv2x86 {

static AsmKind kindFromStr(llvm::StringRef s) {
    if (s == "InlineBasic")    return AsmKind::InlineBasic;
    if (s == "InlineGoto")     return AsmKind::InlineGoto;
    if (s == "FileScope")      return AsmKind::FileScope;
    if (s == "DotSFile")       return AsmKind::DotSFile;
    return AsmKind::InlineExtended;
}

static Category catFromStr(llvm::StringRef s) {
    if (s == "PortableC")         return Category::PortableC;
    if (s == "ReplaceableByRule") return Category::ReplaceableByRule;
    if (s == "NeedsRoute")        return Category::NeedsRoute;
    if (s == "Unsupported")       return Category::Unsupported;
    return Category::NeedsAsmTranslation;
}

static void loadOperands(const llvm::json::Object *obj,
                         const char *key,
                         std::vector<AsmOperand> &out) {
    auto *arr = obj->getArray(key);
    if (!arr) return;

    for (auto &v : *arr) {
        auto *o = v.getAsObject();
        if (!o) continue;

        AsmOperand op;
        if (auto s = o->getString("constraint"))      op.constraint = s->str();
        if (auto s = o->getString("exprText"))        op.exprText = s->str();
        if (auto s = o->getString("symbolicName"))    op.symbolicName = s->str();
        if (auto b = o->getBoolean("isOutput"))       op.isOutput = *b;
        if (auto b = o->getBoolean("isTied"))         op.isTied = *b;
        if (auto b = o->getBoolean("isEarlyClobber")) op.isEarlyClobber = *b;
        out.push_back(std::move(op));
    }
}

static void loadStringArray(const llvm::json::Object *obj,
                            const char *key,
                            std::vector<std::string> &out) {
    auto *arr = obj->getArray(key);
    if (!arr) return;

    for (auto &v : *arr) {
        if (auto s = v.getAsString()) {
            out.push_back(s->str());
        }
    }
}

bool loadReportJSON(const std::string &path, ClassificationReport &rep) {
    auto bufOrErr = llvm::MemoryBuffer::getFile(path);
    if (!bufOrErr) return false;

    auto j = llvm::json::parse((*bufOrErr)->getBuffer());
    if (!j) return false;

    auto *root = j->getAsObject();
    if (!root) return false;

    auto *arr = root->getArray("findings");
    if (!arr) return false;

    rep.findings.clear();

    for (auto &v : *arr) {
        auto *o = v.getAsObject();
        if (!o) continue;

        Finding f;

        if (auto s = o->getString("category")) f.category = catFromStr(*s);

        if (auto s = o->getString("file"))     f.fileName = s->str();
        if (auto s = o->getString("fileName")) f.fileName = s->str();

        if (auto i = o->getInteger("line"))   f.line = static_cast<unsigned>(*i);
        if (auto i = o->getInteger("column")) f.column = static_cast<unsigned>(*i);

        if (auto s = o->getString("description")) f.description = s->str();

        if (auto s = o->getString("rule"))     f.ruleName = s->str();
        if (auto s = o->getString("ruleName")) f.ruleName = s->str();

        if (auto s = o->getString("replacement"))
            f.suggestedReplacement = s->str();
        if (auto s = o->getString("suggestedReplacement"))
            f.suggestedReplacement = s->str();

        if (auto s = o->getString("subjectKind")) f.subjectKind = s->str();
        if (auto s = o->getString("symbolName"))  f.symbolName = s->str();

        if (auto b = o->getBoolean("hasRewriteRange")) f.hasRewriteRange = *b;
        if (auto i = o->getInteger("rewriteBeginOffset"))
            f.rewriteBeginOffset = static_cast<unsigned>(*i);
        if (auto i = o->getInteger("rewriteEndOffset"))
            f.rewriteEndOffset = static_cast<unsigned>(*i);
        if (auto s = o->getString("rawSourceText"))
            f.rawSourceText = s->str();

        if (auto b = o->getBoolean("fromMacroExpansion")) f.fromMacroExpansion = *b;
        if (auto s = o->getString("macroName")) f.macroName = s->str();
        if (auto *a = o->getObject("publicApprovalArtifact")) {
            auto get = [&](const char *key, std::string &out) { if (auto s = a->getString(key)) out = s->str(); };
            f.publicApprovalArtifact.present = true;
            get("artifactVersion", f.publicApprovalArtifact.artifactVersion);
            get("approvalStatus", f.publicApprovalArtifact.approvalStatus);
            get("semanticContractId", f.publicApprovalArtifact.semanticContractId);
            get("semanticContractVersion", f.publicApprovalArtifact.semanticContractVersion);
            get("sourceBuiltin", f.publicApprovalArtifact.sourceBuiltin);
            get("targetEnvironmentId", f.publicApprovalArtifact.targetEnvironmentId);
            get("compilerCapability", f.publicApprovalArtifact.compilerCapability);
            get("compilerFamily", f.publicApprovalArtifact.compilerFamily);
            get("compilerVersion", f.publicApprovalArtifact.compilerVersion);
            loadStringArray(a, "requiredHeaders", f.publicApprovalArtifact.requiredHeaders);
            loadStringArray(a, "requiredTargetFeatures", f.publicApprovalArtifact.requiredTargetFeatures);
            get("rendererRecipeId", f.publicApprovalArtifact.rendererRecipeId);
            get("preservationLevel", f.publicApprovalArtifact.preservationLevel);
            get("fallbackPolicy", f.publicApprovalArtifact.fallbackPolicy);
            get("replacementDigest", f.publicApprovalArtifact.replacementDigest);
            get("sourceSliceDigest", f.publicApprovalArtifact.sourceSliceDigest);
        }
        if (auto *a = o->getObject("approvalArtifact")) {
            auto get = [&](const char *key, std::string &out) { if (auto s = a->getString(key)) out = s->str(); };
            f.approvalArtifact.present = true;
            get("artifactVersion", f.approvalArtifact.artifactVersion); get("proofStatus", f.approvalArtifact.proofStatus); get("sourceFragmentId", f.approvalArtifact.sourceFragmentId); get("sourceModelId", f.approvalArtifact.sourceModelId); get("preservationDecisionId", f.approvalArtifact.preservationDecisionId); get("planId", f.approvalArtifact.planId); get("constraintsId", f.approvalArtifact.constraintsId); get("targetEnvironmentId", f.approvalArtifact.targetEnvironmentId); get("targetCatalogVersion", f.approvalArtifact.targetCatalogVersion); get("selectionPolicyId", f.approvalArtifact.selectionPolicyId); get("selectionPolicyVersion", f.approvalArtifact.selectionPolicyVersion); get("selectionTier", f.approvalArtifact.selectionTier); get("rendererId", f.approvalArtifact.rendererId); get("rendererVersion", f.approvalArtifact.rendererVersion); get("replacementKind", f.approvalArtifact.replacementKind); get("replacementDigest", f.approvalArtifact.replacementDigest); get("sourceSliceDigest", f.approvalArtifact.sourceSliceDigest); get("helperRuntimeContractId", f.approvalArtifact.helperRuntimeContractId); get("helperSemanticVersion", f.approvalArtifact.helperSemanticVersion); get("helperRequiredHeader", f.approvalArtifact.helperRequiredHeader); get("helperRuntimeLibrary", f.approvalArtifact.helperRuntimeLibrary); get("helperRuntimeManifestVersion", f.approvalArtifact.helperRuntimeManifestVersion); get("preservationMode", f.approvalArtifact.preservationMode); get("sourceSemanticContractId", f.approvalArtifact.sourceSemanticContractId); get("targetSemanticContractId", f.approvalArtifact.targetSemanticContractId); if (auto enabled = a->getBoolean("functionalFallbackEnabled")) f.approvalArtifact.functionalFallbackEnabled = *enabled;
        }

        loadStringArray(o, "arguments", f.arguments);
        if (auto *bo = o->getObject("builtin")) {
            BuiltinFinding b;
            if (auto s = bo->getString("calleeName")) b.calleeName = s->str();
            loadStringArray(bo, "args", b.args);
            loadStringArray(bo, "argumentTypeIds", b.argumentTypeIds);
            if (auto *types = bo->getArray("argumentTypes")) {
                for (const auto &entry : *types) if (auto *to = entry.getAsObject()) {
                    BuiltinFinding::TypeContract t;
                    if (auto s = to->getString("canonicalType")) t.canonicalType = s->str();
                    if (auto i = to->getInteger("widthBits")) t.widthBits = static_cast<unsigned>(*i);
                    if (auto v = to->getBoolean("isSigned")) t.isSigned = *v;
                    if (auto v = to->getBoolean("isPointer")) t.isPointer = *v;
                    if (auto i = to->getInteger("alignmentBytes")) t.alignmentBytes = static_cast<unsigned>(*i);
                    if (auto s = to->getString("pointeeCanonicalType")) t.pointeeCanonicalType = s->str();
                    if (auto s = to->getString("qualifiers")) t.qualifiers = s->str();
                    b.argumentTypes.push_back(std::move(t));
                }
            }
            if (auto s = bo->getString("resultTypeId")) b.resultTypeId = s->str();
            if (auto v = bo->getBoolean("resultIsLValue")) b.resultIsLValue = *v;
            if (auto *to = bo->getObject("resultType")) {
                if (auto s = to->getString("canonicalType")) b.resultType.canonicalType = s->str();
                if (auto i = to->getInteger("widthBits")) b.resultType.widthBits = static_cast<unsigned>(*i);
                if (auto v = to->getBoolean("isSigned")) b.resultType.isSigned = *v;
                if (auto v = to->getBoolean("isPointer")) b.resultType.isPointer = *v;
                if (auto i = to->getInteger("alignmentBytes")) b.resultType.alignmentBytes = static_cast<unsigned>(*i);
                if (auto s = to->getString("pointeeCanonicalType")) b.resultType.pointeeCanonicalType = s->str();
                if (auto s = to->getString("qualifiers")) b.resultType.qualifiers = s->str();
            }
            if (!b.calleeName.empty()) f.builtin = std::move(b);
        }

        if (auto *fo = o->getObject("fragment")) {
            AsmFragment g;

            if (auto s = fo->getString("kind"))              g.kind = kindFromStr(*s);

            if (auto s = fo->getString("rawAsmText"))
                g.rawAsmText = s->str();
            if (g.rawAsmText.empty()) {
                if (auto s = fo->getString("asmText"))
                    g.rawAsmText = s->str();
            }

            if (auto b = fo->getBoolean("isVolatile"))       g.isVolatile = *b;
            if (auto s = fo->getString("fileName"))          g.fileName = s->str();
            if (auto i = fo->getInteger("line"))             g.line = static_cast<unsigned>(*i);
            if (auto i = fo->getInteger("column"))           g.column = static_cast<unsigned>(*i);
            if (auto i = fo->getInteger("beginOffset"))      g.beginOffset = static_cast<unsigned>(*i);
            if (auto i = fo->getInteger("endOffset"))        g.endOffset = static_cast<unsigned>(*i);
            if (auto s = fo->getString("enclosingFunction")) g.enclosingFunction = s->str();
            if (auto s = fo->getString("id"))                g.id = s->str();

            loadOperands(fo, "outputs", g.outputs);
            loadOperands(fo, "inputs", g.inputs);
            loadStringArray(fo, "clobbers", g.clobbers);
            loadStringArray(fo, "gotoLabels", g.gotoLabels);
            if (auto *edges = fo->getArray("gotoEdges")) {
                for (auto &value : *edges) {
                    auto *edge = value.getAsObject();
                    if (!edge) continue;
                    AsmGotoEdge parsed;
                    if (auto s = edge->getString("asmTarget")) parsed.asmTarget = s->str();
                    if (auto s = edge->getString("cLabel")) parsed.cLabel = s->str();
                    if (auto i = edge->getInteger("exitCode")) parsed.exitCode = static_cast<unsigned>(*i);
                    if (auto s = edge->getString("targetContinuationId")) parsed.targetContinuationId = s->str();
                    if (!parsed.asmTarget.empty() && !parsed.cLabel.empty() && !parsed.targetContinuationId.empty())
                        g.gotoEdges.push_back(std::move(parsed));
                }
            }
            if (auto s = fo->getString("asmGotoFallthroughContinuationId"))
                g.asmGotoFallthroughContinuationId = s->str();
            if (auto s = fo->getString("asmGotoConditionKind")) g.asmGotoConditionKind = s->str();
            if (auto i = fo->getInteger("asmGotoConditionOperandIndex")) g.asmGotoConditionOperandIndex = static_cast<int>(*i);
            loadStringArray(fo, "asmGotoSuccessorContinuationIds", g.asmGotoSuccessorContinuationIds);
            if (auto b = fo->getBoolean("asmGotoControlFlowComplete"))
                g.asmGotoControlFlowComplete = *b;

            f.fragment = std::move(g);
        }

        // 兼容旧报告：如果没有通用 rewrite range，但 fragment 里有区间，就回填
        if (!f.hasRewriteRange && f.fragment.has_value()) {
            f.hasRewriteRange = true;
            f.rewriteBeginOffset = f.fragment->beginOffset;
            f.rewriteEndOffset = f.fragment->endOffset;
            if (f.subjectKind.empty()) f.subjectKind = "AsmFragment";
        }

        rep.findings.push_back(std::move(f));
    }

    return true;
}

} // namespace riscv2x86
