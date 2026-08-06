// 1) 简单整数（验证 add/addw/sub 等）
long simple_add(long a, long b) {
    long r;
    __asm__("add %0, %1, %2" : "=r"(r) : "r"(a), "r"(b));
    return r;
}
int  addw_sx(int a, int b) {
    int r;
    __asm__("addw %0, %1, %2" : "=r"(r) : "r"(a), "r"(b));
    return r;
}

// 2) off(rs) 访存
int  load_off(const int *base) {
    int r;
    __asm__("lw %0, 8(%1)" : "=r"(r) : "r"(base) : "memory");
    return r;
}
void store_off(int *base, int v) {
    __asm__("sw %0, 0(%1)" : : "r"(v), "r"(base) : "memory");
}

// 3) W 系符号扩展边界
long sllw_neg(long x) {
    long r;
    __asm__("sllw %0, %1, %2" : "=r"(r) : "r"(x), "r"(1L));
    return r;
}