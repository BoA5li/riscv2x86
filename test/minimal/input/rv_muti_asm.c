typedef long long i64;

i64 f(i64 a, i64 b) {
    i64 result;

    __asm__("add %0, %1, %2"
            : "=r"(result)
            : "r"(a), "r"(b));

    __asm__("addi %0, %0, 1"
            : "+r"(result));

    return result;
}