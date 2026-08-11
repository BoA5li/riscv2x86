#include "riscv2x86/RuleEngine.h"

namespace riscv2x86 {

void registerBuiltinRules(RuleEngine &) {
    // Deliberately empty.
    //
    // No RISC-V target builtin currently has a registered Replace contract.
    // rdcycle is timing/microarchitecture-sensitive and must be routed; an
    // asm "nop" likewise cannot be made replaceable by raw template text.
    // Future public replacements are admitted only through
    // PublicReplacementContract + structured AST type matching in RuleEngine.
}

} // namespace riscv2x86
