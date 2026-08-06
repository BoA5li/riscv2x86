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