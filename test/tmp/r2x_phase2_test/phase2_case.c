typedef unsigned long long u64;

static u64 read_cycle_from_asm(void) {
    u64 v = 0;
    __asm__ volatile ("rdcycle %0" : "=r"(v));
    return v;
}

u64 demo(void) {
    u64 a = 0;
    __asm__ volatile ("rdcycle %0" : "=r"(a));
    __asm__ volatile ("nop");
    return a + read_cycle_from_asm();
}