#include <stdint.h>

void rv_memory_barrier_like(void) {
    __asm__ volatile(
        ""
        :
        :
        : "memory"
    );
}

int main(void) {
    rv_memory_barrier_like();
    return 0;
}