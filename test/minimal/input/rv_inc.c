typedef long long i64;

i64 rv_inc(i64 value) {
    __asm__(
        "addi %0, %0, 1"
        : "+r"(value)
    );

    return value;
}