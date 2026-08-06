#include <stddef.h>

int atomic_add(int *p, int v) {
    int old;
    __asm__ __volatile__("amoadd.w %0, %2, %1"
                         : "=r"(old), "+A"(*p)
                         : "r"(v)
                         : "memory");
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