#include <stddef.h>

int atomic_add(int *p, int v) {
    int old;
    /* riscv2x86: replaced by rule atomic.amoadd */ old = __atomic_fetch_add(&(*p), v, __ATOMIC_RELAXED);
    return old;
}

void mem_barrier(void) {
    __asm__ __volatile__("fence rw,rw" ::: "memory");
}

int cas_strong(int *p, int expected, int desired) {
    int old, sc;
    __asm__ __volatile__(
        "1: lr.w %0, %1\n"
        "   bne  %0, %3, 2f\n"
        "   sc.w %2, %4, %1\n"
        "   bnez %2, 1b\n"
        "2:\n"
        : "=&r"(old), "+A"(*p), "=&r"(sc)
        : "r"(expected), "r"(desired)
        : "memory");
    return old;
}