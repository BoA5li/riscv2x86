#include <stdint.h>

uint64_t rv2x86_register_sub(uint64_t auxiliary0 __attribute__((unused)),
                           uint32_t auxiliary1 __attribute__((unused)),
                           uint64_t auxiliary2 __attribute__((unused)),
                           uint32_t auxiliary3 __attribute__((unused)),
                           uint64_t value, uint32_t *object)
{
    uint64_t old, next, status;
    __asm__ volatile(
        "1: lr.w.aq %[old],(%[address])\n\t"
        "subw %[next],%[old],%[input]\n\t"
        "sc.w.rl %[status],%[next],(%[address])\n\t"
        "bnez %[status],1b"
        : [old] "=&r" (old), [next] "=&r" (next),
          [status] "=&r" (status), [object] "+A" (*object)
        : [address] "r" (object), [input] "r" (value)
        : "memory");
    return next;
}
