#include "riscv2x86/Rewriter.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <sstream>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace riscv2x86 {

namespace {
static std::string approvalDigest(const std::string &value) {
    std::uint64_t state = 14695981039346656037ULL;
    for (unsigned char byte : value) state = (state ^ byte) * 1099511628211ULL;
    std::ostringstream out; out << "fnv1a64:" << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << state;
    return out.str();
}

static bool validApprovalArtifact(const Finding &f, const std::string &sourceSlice) {
    const auto &a = f.approvalArtifact;
    // Phase 2 public rules predate Phase 6 and retain their own RuleEngine
    // contract.  Every Phase 6-produced replacement is proof-gated here.
    if (f.ruleName.rfind("phase6.", 0) != 0) return true;
    if (!a.present || a.artifactVersion != "phase6-approval-v1" || a.proofStatus != "approved") return false;
    if (a.sourceFragmentId.empty() || a.planId.empty() || a.constraintsId.empty() || a.targetEnvironmentId.empty() || a.rendererId.empty() || a.rendererVersion.empty() || a.replacementKind.empty()) return false;
    if (!f.fragment.has_value() || a.sourceFragmentId != f.fragment->id) return false;
    return a.replacementDigest == approvalDigest(f.suggestedReplacement) && a.sourceSliceDigest == approvalDigest(sourceSlice);
}

fs::path normalizePath(const fs::path &p) {
    std::error_code ec;
    fs::path abs = fs::absolute(p, ec);
    if (ec) {
        return p.lexically_normal();
    }
    return abs.lexically_normal();
}

bool isSamePath(const fs::path &a, const fs::path &b) {
    return normalizePath(a) == normalizePath(b);
}

bool isUnderRoot(const fs::path &p, const fs::path &root) {
    std::error_code ec;
    fs::path rel = fs::relative(normalizePath(p), normalizePath(root), ec);
    if (ec) return false;
    if (rel.empty()) return true;
    auto it = rel.begin();
    return it != rel.end() && *it != "..";
}

fs::path resolveToSourcePath(const fs::path &orig, const fs::path &srcRootAbs) {
    fs::path cand1 = normalizePath(orig);
    if (isUnderRoot(cand1, srcRootAbs)) {
        return cand1;
    }

    if (orig.is_relative()) {
        fs::path cand2 = normalizePath(srcRootAbs / orig);
        if (isUnderRoot(cand2, srcRootAbs)) {
            return cand2;
        }
    }

    return fs::path();
}

static bool startsWith(const std::string &s, const std::string &prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

static std::string ltrimCopy(const std::string &s) {
    std::size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
        ++i;
    }
    return s.substr(i);
}

static bool contentUsesStdintTypes(const std::string &content) {
    static const char *tokens[] = {
        "uint64_t", "int64_t",
        "uint32_t", "int32_t",
        "uint16_t", "int16_t",
        "uint8_t",  "int8_t"
    };
    for (const char *tok : tokens) {
        if (content.find(tok) != std::string::npos) {
            return true;
        }
    }
    return false;
}

static bool hasStdintInclude(const std::string &content) {
    return content.find("#include <stdint.h>") != std::string::npos ||
           content.find("#include \"stdint.h\"") != std::string::npos;
}

static std::size_t findStdintInsertPos(const std::string &content) {
    std::size_t pos = 0;

    // UTF-8 BOM
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF) {
        pos = 3;
    }

    std::size_t cur = pos;
    std::size_t lastIncludeEnd = std::string::npos;
    bool inBlockComment = false;

    while (cur < content.size()) {
        std::size_t lineEnd = content.find('\n', cur);
        std::size_t next = (lineEnd == std::string::npos) ? content.size() : lineEnd + 1;
        std::string line = content.substr(cur, next - cur);
        std::string t = ltrimCopy(line);

        if (inBlockComment) {
            if (t.find("*/") != std::string::npos) {
                inBlockComment = false;
            }
            cur = next;
            continue;
        }

        if (startsWith(t, "/*")) {
            if (t.find("*/") == std::string::npos) {
                inBlockComment = true;
            }
            cur = next;
            continue;
        }

        if (startsWith(t, "//") || t.empty() || t == "\n" || t == "\r\n") {
            cur = next;
            continue;
        }

        if (startsWith(t, "#pragma once")) {
            return next;
        }

        if (startsWith(t, "#include")) {
            lastIncludeEnd = next;
            cur = next;
            continue;
        }

        if (lastIncludeEnd != std::string::npos) {
            return lastIncludeEnd;
        }

        return pos;
    }

    if (lastIncludeEnd != std::string::npos) {
        return lastIncludeEnd;
    }
    return pos;
}

static void ensureStdintInclude(std::string &content) {
    if (!contentUsesStdintTypes(content)) return;
    if (hasStdintInclude(content)) return;

    const std::size_t pos = findStdintInsertPos(content);
    const std::string inc = "#include <stdint.h>\n";

    if (pos >= content.size()) {
        if (!content.empty() && content.back() != '\n') {
            content.push_back('\n');
        }
        content += inc;
    } else {
        content.insert(pos, inc);
    }
}

enum class ApplyMode {
    Skip,
    RuleRewrite,
    LowerToC,
    LowerToX86InlineAsm,
};

static ApplyMode classifyApplyMode(const Finding &f) {
    // 没 replacement 的 finding，一律不做源码替换
    if (f.suggestedReplacement.empty()) {
        return ApplyMode::Skip;
    }

    // 非“可回填” finding 不做替换
    if (f.category != Category::ReplaceableByRule) {
        return ApplyMode::Skip;
    }

    // phase6 / phase7 产物：显式分流
    if (startsWith(f.ruleName, "phase6.")) {
        if (f.ruleName == "phase6.keep" ||
            f.ruleName == "phase6.keep_c" ||
            f.ruleName == "phase6.preserve") {
            return ApplyMode::Skip;
        }

        if (startsWith(f.ruleName, "phase6.lower_to_x86_") ||
            startsWith(f.ruleName, "phase6.x86_")) {
            return ApplyMode::LowerToX86InlineAsm;
        }

        // 其余 phase6.* 成功产物，统一按“降到 C”处理
        return ApplyMode::LowerToC;
    }

    // 传统规则引擎命中的 replacement
    return ApplyMode::RuleRewrite;
}

static std::string buildAnnotation(ApplyMode mode, const std::string &ruleName) {
    switch (mode) {
    case ApplyMode::RuleRewrite:
        if (!ruleName.empty()) {
            return "/* riscv2x86: replaced by rule " + ruleName + " */ ";
        }
        return "/* riscv2x86: rewritten */ ";

    case ApplyMode::LowerToC:
        return "/* riscv2x86: lowered from RISC-V asm to C */ ";

    case ApplyMode::LowerToX86InlineAsm:
        return "/* riscv2x86: lowered from RISC-V asm to x86 inline asm */ ";

    case ApplyMode::Skip:
    default:
        return "";
    }
}

} // namespace

SourceRewriter::SourceRewriter(const std::string &src, const std::string &out)
    : sourceRoot_(src), outputDir_(out) {}

void SourceRewriter::copyTree() {
    std::error_code ec;
    fs::create_directories(outputDir_, ec);
    if (ec) {
        std::cerr << "[rewrite] failed to create output dir: " << outputDir_
                  << " : " << ec.message() << "\n";
        return;
    }

    fs::path srcRootAbs = normalizePath(sourceRoot_);
    fs::path outDirAbs  = normalizePath(outputDir_);

    for (const auto &entry : fs::recursive_directory_iterator(sourceRoot_)) {
        fs::path cur = entry.path();

        if (isUnderRoot(cur, outDirAbs)) {
            continue;
        }

        std::error_code relEc;
        fs::path rel = fs::relative(normalizePath(cur), srcRootAbs, relEc);
        if (relEc) {
            std::cerr << "[rewrite] failed to compute relative path for "
                      << cur << " : " << relEc.message() << "\n";
            continue;
        }

        fs::path dst = fs::path(outputDir_) / rel;

        if (entry.is_directory()) {
            std::error_code dirEc;
            fs::create_directories(dst, dirEc);
            if (dirEc) {
                std::cerr << "[rewrite] failed to create dir " << dst
                          << " : " << dirEc.message() << "\n";
            }
        } else if (entry.is_regular_file()) {
            std::error_code mkEc;
            fs::create_directories(dst.parent_path(), mkEc);
            if (mkEc) {
                std::cerr << "[rewrite] failed to create parent dir for " << dst
                          << " : " << mkEc.message() << "\n";
                continue;
            }

            std::error_code cpEc;
            fs::copy_file(cur, dst, fs::copy_options::overwrite_existing, cpEc);
            if (cpEc) {
                std::cerr << "[rewrite] failed to copy " << cur << " -> " << dst
                          << " : " << cpEc.message() << "\n";
            }
        }
    }
}

std::string SourceRewriter::mapPath(const std::string &orig) const {
    fs::path srcRootAbs = normalizePath(sourceRoot_);
    fs::path outDirAbs  = normalizePath(outputDir_);

    fs::path resolved = resolveToSourcePath(fs::path(orig), srcRootAbs);
    if (resolved.empty()) {
        return "";
    }

    std::error_code ec;
    fs::path rel = fs::relative(resolved, srcRootAbs, ec);
    if (ec) {
        return "";
    }

    fs::path dst = outDirAbs / rel;
    return dst.string();
}

int SourceRewriter::rewrite(const ClassificationReport &report) {
    copyTree();

    struct Edit {
        std::size_t beginOffset;
        std::size_t endOffset;
        std::string replacement;
        std::string ruleName;
        ApplyMode mode;
        const Finding *finding;
    };

    std::map<std::string, std::vector<Edit>> byFile;

    for (const auto &f : report.findings) {
        ApplyMode mode = classifyApplyMode(f);
        if (mode == ApplyMode::Skip) continue;

        std::string origPath = !f.fileName.empty()
                             ? f.fileName
                             : (f.fragment.has_value() ? f.fragment->fileName : "");

        if (origPath.empty()) {
            std::cerr << "[rewrite] skip finding without file path\n";
            continue;
        }

        std::string dstPath = mapPath(origPath);
        if (dstPath.empty()) {
            std::cerr << "[rewrite] skip unmapped file: " << origPath << "\n";
            continue;
        }

        std::size_t beginOffset = 0;
        std::size_t endOffset = 0;

        if (f.rewriteEndOffset > f.rewriteBeginOffset) {
            beginOffset = static_cast<std::size_t>(f.rewriteBeginOffset);
            endOffset = static_cast<std::size_t>(f.rewriteEndOffset);
        } else if (f.fragment.has_value()) {
            beginOffset = static_cast<std::size_t>(f.fragment->beginOffset);
            endOffset = static_cast<std::size_t>(f.fragment->endOffset);
        } else {
            std::cerr << "[rewrite] skip finding without rewrite range: "
                      << origPath << ":" << f.line << ":" << f.column << "\n";
            continue;
        }

        byFile[dstPath].push_back(Edit{
            beginOffset,
            endOffset,
            f.suggestedReplacement,
            f.ruleName,
            mode, &f
        });
    }

    int count = 0;

    for (auto &kv : byFile) {
        const std::string &path = kv.first;
        auto &edits = kv.second;

        std::sort(edits.begin(), edits.end(),
                  [](const Edit &a, const Edit &b) {
                      if (a.beginOffset != b.beginOffset) {
                          return a.beginOffset > b.beginOffset;
                      }
                      return a.endOffset > b.endOffset;
                  });

        bool hasOverlap = false;
        std::size_t previousBegin = static_cast<std::size_t>(-1);

        for (const auto &e : edits) {
            if (previousBegin != static_cast<std::size_t>(-1) &&
                e.endOffset > previousBegin) {
                std::cerr << "[rewrite] overlapping edits in " << path
                          << " around [" << e.beginOffset << ", " << e.endOffset
                          << ")\n";
                hasOverlap = true;
                break;
            }
            previousBegin = e.beginOffset;
        }

        if (hasOverlap) {
            continue;
        }

        std::ifstream in(path, std::ios::binary);
        if (!in) {
            std::cerr << "[rewrite] cannot open " << path << "\n";
            continue;
        }

        std::ostringstream ss;
        ss << in.rdbuf();
        std::string content = ss.str();
        in.close();

        for (const auto &e : edits) {
            if (e.beginOffset > e.endOffset || e.endOffset > content.size()) {
                std::cerr << "[rewrite] offset out of range in " << path
                          << " [" << e.beginOffset << ", " << e.endOffset
                          << "), file size=" << content.size() << "\n";
                continue;
            }
            const std::string sourceSlice = content.substr(e.beginOffset, e.endOffset - e.beginOffset);
            if (!validApprovalArtifact(*e.finding, sourceSlice)) {
                std::cerr << "[rewrite] reject unapproved or mismatched Phase-6 artifact in " << path << "\n";
                continue;
            }

            const std::string ann = buildAnnotation(e.mode, e.ruleName);

            content.replace(e.beginOffset,
                            e.endOffset - e.beginOffset,
                            ann + e.replacement);
            ++count;
        }

        ensureStdintInclude(content);

        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "[rewrite] cannot write " << path << "\n";
            continue;
        }

        out << content;
    }

    return count;
}

} // namespace riscv2x86
