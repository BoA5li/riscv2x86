unsigned long read_cycle(void) {
    unsigned long c;
    /* riscv2x86: replaced by rule builtin.rdcycle */ c = (typeof(c))__builtin_readcyclecounter();
    return c;
}