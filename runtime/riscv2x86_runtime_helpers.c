#include "riscv2x86_runtime_helpers.h"

uint64_t riscv2x86_rt_rv64_mulhu_u64(uint64_t lhs, uint64_t rhs) {
    return (uint64_t)(((__uint128_t)lhs * (__uint128_t)rhs) >> 64);
}

void riscv2x86_rt_instruction_stream_sync_local(void) {
#if defined(__x86_64__) || defined(__i386__)
    /* CPUID is the registered architectural serializing operation for this
     * local SMC contract.  It is deliberately not emitted by Phase 6F as an
     * ad-hoc asm template: its register clobbers stay contained by this ABI. */
    unsigned int eax = 0, ebx, ecx = 0, edx;
    __asm__ volatile ("cpuid"
                      : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx)
                      :
                      : "memory", "cc");
#else
# error "instruction-stream synchronization runtime requires x86"
#endif
}
