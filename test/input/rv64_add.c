#include <stdint.h>

uint64_t rv64_add(uint64_t lhs, uint64_t rhs)
{
    uint64_t out;

    __asm__ volatile (
        "add %[dst], %[lhs], %[rhs]"
        : [dst] "=r"(out)
        : [lhs] "r"(lhs),
          [rhs] "r"(rhs)
    );

    return out;
}