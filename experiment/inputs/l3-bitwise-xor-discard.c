#include <stdint.h>

void rv2x86_probe_atomic_xor_discard(uint32_t *address, uint64_t value) {
    __asm__ volatile("amoxor.w.rl zero,%1,%0"
        : "+A"(*address)
        : "r"(value)
        : "memory");
}
