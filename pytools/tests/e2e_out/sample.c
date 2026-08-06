// test/e2e/sample.c
int amo_add(int *p, int v) {
    int old;
    /* riscv2x86: replaced by rule atomic.amoadd */ old = __atomic_fetch_add(&(*p), v, __ATOMIC_SEQ_CST);
    return old;
}

void barrier(void) {
    /* riscv2x86: replaced by rule atomic.fence */ __atomic_thread_fence(__ATOMIC_SEQ_CST);
}