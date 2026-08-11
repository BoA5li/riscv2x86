#include "riscv2x86/RuleEngine.h"

namespace riscv2x86 {

void registerAtomicRules(RuleEngine &) {
    // Deliberately empty.
    //
    // RISC-V amo*/lr/sc/fence source text is not a public C interface.  In
    // particular, a memory clobber is not a hardware fence, .aq/.rl bits do
    // not by themselves prove a C memory-order mapping, and a regex cannot
    // establish object type, alignment, result binding or CAS failure order.
    // Such findings must remain NeedsAsmTranslation and enter the proof-gated
    // Phase 4--6 path (or become structured needs_route/unsupported).
}

} // namespace riscv2x86
