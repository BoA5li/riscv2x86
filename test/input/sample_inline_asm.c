unsigned long read_cycle(void) {
    unsigned long c;
    __asm__ __volatile__("rdcycle %0" : "=r"(c));
    return c;
}