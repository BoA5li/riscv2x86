typedef long long i64;

i64 rv_add_named(i64 a, i64 b) {
    i64 result;

    __asm__(
        "add %[out], %[lhs], %[rhs]"
        : [out] "=r"(result)
        : [lhs] "r"(a),
          [rhs] "r"(b)
    );

    return result;
}