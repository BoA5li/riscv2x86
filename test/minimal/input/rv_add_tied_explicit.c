typedef long long i64;

i64 rv_add_tied_explicit(i64 value, i64 increment) {
    i64 result;

    __asm__(
        "add %0, %1, %2"
        : "=r"(result)
        : "0"(value), "r"(increment)
    );

    return result;
}