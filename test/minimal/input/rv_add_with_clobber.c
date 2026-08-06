typedef long long i64;

i64 rv_add_with_clobber(i64 a, i64 b) {
    i64 result;

    __asm__ volatile(
        "add %0, %1, %2"
        : "=r"(result)
        : "r"(a), "r"(b)
        : "t0"
    );

    return result;
}