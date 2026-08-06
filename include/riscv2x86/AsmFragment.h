#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace riscv2x86 {

// 单个操作数的约束与绑定
struct AsmOperand {
    std::string constraint;       // 例如 "r", "=r", "+m", "I"
    std::string exprText;         // 对应的 C 表达式原始文本
    std::string symbolicName;     // [name] 形式的符号名（可空）
    bool isOutput = false;
    bool isTied = false;
    bool isEarlyClobber = false;
};

// asm 片段类型
enum class AsmKind {
    InlineBasic,      // 基本 asm("...")
    InlineExtended,   // asm(... : ... : ... : ...)
    InlineGoto,       // asm goto
    FileScope,        // 顶层 asm
    DotSFile          // .S 文件（独立处理）
};

struct AsmFragment {
    AsmKind kind;
    std::string rawAsmText;                 // 模板原文
    std::vector<AsmOperand> outputs;
    std::vector<AsmOperand> inputs;
    std::vector<std::string> clobbers;      // 包含 "memory", "cc" 等
    std::vector<std::string> gotoLabels;
    bool isVolatile = false;

    // GNU inline asm operand index -> host C/C++ expression width in bits.
    //
    // GNU operand 编号规则：
    //   outputs: 0 .. getNumOutputs() - 1
    //   inputs:  getNumOutputs() .. getNumOutputs() + getNumInputs() - 1
    //
    // 例如：
    //   : "=r"(result)
    //   : "r"(a), "r"(b)
    //
    // 则：
    //   operandWidthBits[0] == width(result)
    //   operandWidthBits[1] == width(a)
    //   operandWidthBits[2] == width(b)
    //
    // 这是来自 Clang AST type analysis 的源级事实，而不是寄存器宽度。
    std::map<unsigned, unsigned> operandWidthBits;

    // 源码位置
    std::string fileName;
    unsigned line = 0;
    unsigned column = 0;
    unsigned beginOffset = 0;     // 在源文件中的字节偏移
    unsigned endOffset = 0;

    // 所属函数
    std::string enclosingFunction;

    // 唯一 id（用于后续阶段索引）
    std::string id;
};

} // namespace riscv2x86