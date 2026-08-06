
typedef long long i64;

i64 rv_add_sub(i64 a, i64 b) {
    i64 result;

    __asm__(
        "add %0, %1, %2\n\t"
        "sub %0, %0, %2"
        : "=r"(result)
        : "r"(a), "r"(b)
    );

    return result;
}