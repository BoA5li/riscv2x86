typedef long long i64;

i64 rv_addi_imm(i64 value) {
    i64 result;

    __asm__(
        "addi %0, %1, %2"
        : "=r"(result)
        : "r"(value), "i"(7)
    );

    return result;
}