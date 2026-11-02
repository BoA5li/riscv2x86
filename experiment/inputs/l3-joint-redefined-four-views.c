#include <stdint.h>

uint64_t rv2x86_transfer_views(uint64_t *first, uint64_t *second,
                               uint64_t *third, uint64_t *fourth) {
    uint64_t value;
    __asm__ volatile ("ld %0,0(%1)" : "=r"(value) : "r"(first) : "memory");
    __asm__ volatile ("sd %0,0(%1)" : : "r"(value), "r"(second) : "memory");
    __asm__ volatile ("ld %0,0(%1)" : "=r"(value) : "r"(third) : "memory");
    __asm__ volatile ("sd %0,0(%1)" : : "r"(value), "r"(fourth) : "memory");
    return value;
}
