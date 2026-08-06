#pragma once
#include "Report.h"
#include <string>

namespace riscv2x86 {

class SourceRewriter {
public:
    // outputDir：把改写后的工程整体复制并改写到该目录
    SourceRewriter(const std::string &sourceRoot, const std::string &outputDir);

    // 根据报告中的 ReplaceableByRule 项执行回填
    // 返回成功改写的条目数
    int rewrite(const ClassificationReport &report);

private:
    std::string sourceRoot_;
    std::string outputDir_;

    void copyTree();
    std::string mapPath(const std::string &origPath) const;
};

} // namespace riscv2x86