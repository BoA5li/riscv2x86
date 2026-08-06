#include <stdint.h>

int64_t rv_add_volatile(int64_t a, int64_t b) {
    int64_t result;

    __asm__ volatile(
        "add %0, %1, %2"
        : "=r"(result)
        : "r"(a), "r"(b)
    );

    return result;
}

int main(void) {
    return rv_add_volatile(20, 22) != 42;
}