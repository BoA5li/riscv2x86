#include <stdint.h>

int64_t rv_add_plain(int64_t a, int64_t b) {
    int64_t result;

    __asm__(
        "add %0, %1, %2"
        : "=r"(result)
        : "r"(a), "r"(b)
    );

    return result;
}

int main(void) {
    return rv_add_plain(20, 22) != 42;
}