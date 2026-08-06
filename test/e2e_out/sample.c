#include <stdint.h>
// test/e2e/sample.c
int amo_add(int *p, int v) {
    int old;
    /* riscv2x86: replaced by rule phase6.pure_c */ old = __atomic_fetch_add(&(*p), v, __ATOMIC_RELAXED);
    return old;
}

void barrier(void) {
    /* riscv2x86: replaced by rule phase6.pure_c */ __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

// test/e2e/sample.c 末尾追加：
int cas_strong(int *p, int expected, int desired) {
    int old;
    int sc;
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  __typeof__(expected) __r2x_old_32 = (expected);
  (void)__atomic_compare_exchange_n(&(*p), &__r2x_old_32, (desired), /*weak=*/0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
  old = __r2x_old_32;
} while (0);
    (void)sc;
    return old;
}

int cas_weak(int *p, int expected, int desired) {
    int old;
    int sc;
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  __typeof__(expected) __r2x_old_32 = (expected);
  (void)__atomic_compare_exchange_n(&(*p), &__r2x_old_32, (desired), /*weak=*/1, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
  old = __r2x_old_32;
} while (0);
    (void)sc;
    return old;
}

// 1) 简单整数（验证 add/addw/sub 等）
long simple_add(long a, long b) {
    long r;
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  uint64_t __r2x_in_x10 = (uint64_t)(0);
  uint64_t __r2x_in_x11 = (uint64_t)(a);
  uint64_t __r2x_in_x12 = (uint64_t)(b);
  uint64_t __r2x_state_a0 = ((uint64_t)__r2x_in_x10);
  uint64_t __r2x_t0 = (uint64_t)((((uint64_t)__r2x_in_x11) + ((uint64_t)__r2x_in_x12)));
  __r2x_state_a0 = ((uint64_t)__r2x_t0);
  r = ((uint64_t)__r2x_state_a0);
} while (0);
    return r;
}
int  addw_sx(int a, int b) {
    int r;
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  uint64_t __r2x_in_x10 = (uint64_t)(0);
  uint64_t __r2x_in_x11 = (uint64_t)(a);
  uint64_t __r2x_in_x12 = (uint64_t)(b);
  uint64_t __r2x_state_a0 = ((uint64_t)__r2x_in_x10);
  uint64_t __r2x_t0 = (uint64_t)(((int64_t)(int32_t)((uint32_t)((uint64_t)__r2x_in_x11) + (uint32_t)((uint64_t)__r2x_in_x12))));
  __r2x_state_a0 = ((uint64_t)__r2x_t0);
  r = ((uint64_t)__r2x_state_a0);
} while (0);
    return r;
}

// 2) off(rs) 访存
int  load_off(const int *base) {
    int r;
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  uint64_t __r2x_in_x10 = (uint64_t)(0);
  uint64_t __r2x_in_x11 = (uint64_t)(base);
  uint64_t __r2x_state_a0 = ((uint64_t)__r2x_in_x10);
  uint64_t __r2x_t0 = (uint64_t)(((int64_t)*(int32_t*)((char*)((uint64_t)__r2x_in_x11) + (8))));
  __r2x_state_a0 = ((uint64_t)__r2x_t0);
  r = ((uint64_t)__r2x_state_a0);
} while (0);
    return r;
}
void store_off(int *base, int v) {
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  uint64_t __r2x_in_x10 = (uint64_t)(v);
  uint64_t __r2x_in_x11 = (uint64_t)(base);
  *(uint32_t*)((char*)((uint64_t)__r2x_in_x11) + (0)) = (uint32_t)((uint64_t)__r2x_in_x10);
} while (0);
}

// 3) W 系符号扩展边界
long sllw_neg(long x) {
    long r;
    /* riscv2x86: replaced by rule phase6.pure_c */ do {
  uint64_t __r2x_in_x10 = (uint64_t)(0);
  uint64_t __r2x_in_x11 = (uint64_t)(x);
  uint64_t __r2x_in_x12 = (uint64_t)(1L);
  uint64_t __r2x_state_a0 = ((uint64_t)__r2x_in_x10);
  uint64_t __r2x_t0 = (uint64_t)(((int64_t)(int32_t)((uint32_t)((uint64_t)__r2x_in_x11) << (((uint64_t)__r2x_in_x12) & 31))));
  __r2x_state_a0 = ((uint64_t)__r2x_t0);
  r = ((uint64_t)__r2x_state_a0);
} while (0);
    return r;
}