typedef long long i64;

i64 rv_add_named(i64 a, i64 b) {
    i64 result;

    /* riscv2x86: lowered from RISC-V asm to x86 inline asm */ __asm__ __volatile__(
        "movq %[in_a1], %%rax\n\t"
        "addq %[in_a2], %%rax\n\t"
        "movq %%rax, %[out_a0]\n\t"
        : [out_a0] "=r" (result)
        : [in_a1] "r" (a),
              [in_a2] "r" (b)
        : "rax", "cc"
    );

    return result;
}