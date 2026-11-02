#include <stdint.h>
uint64_t rv2x86_atomic_call(uint64_t unused __attribute__((unused)), uint32_t aux __attribute__((unused)), uint64_t v, uint32_t *p) {
    uint64_t old;
    __asm__ volatile("amoxor.w.aqrl %0,%2,%1" : "=r"(old), "+A"(*p) : "r"(v) : "memory");
    return old;
}
