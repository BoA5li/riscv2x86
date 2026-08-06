typedef long long i64;

i64 rv_add_tied(i64 value, i64 increment) {
    __asm__(
        "add %0, %0, %1"
        : "+r"(value)
        : "r"(increment)
    );

    return value;
}