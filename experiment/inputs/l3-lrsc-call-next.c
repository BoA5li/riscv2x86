#include <stdint.h>
uint64_t rv2x86_lrsc_call(uint64_t value, uint32_t unused __attribute__((unused)), uint32_t *p) {
    uint64_t old, next, status;
    __asm__ volatile("1: lr.w.aq %[old],(%[p])\n\taddw %[next],%[old],%[value]\n\tsc.w.rl %[status],%[next],(%[p])\n\tbnez %[status],1b"
        : [old]"=&r"(old), [next]"=&r"(next), [status]"=&r"(status), [object]"+A"(*p)
        : [p]"r"(p), [value]"r"(value) : "memory");
    return next;
}
