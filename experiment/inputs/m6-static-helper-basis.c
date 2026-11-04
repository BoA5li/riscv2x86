/* Call-target inspection seed, NOT an approved M6 execution route. */
static unsigned long update(unsigned long *address, unsigned long input) {
    unsigned long loaded, result;
    __asm__ volatile("ld %0,8(%1)" : "=r"(loaded) : "r"(address) : "memory");
    __asm__ volatile("add %0,%1,%2" : "=r"(result) : "r"(loaded), "r"(input));
    __asm__ volatile("sd %0,16(%1)" : : "r"(result), "r"(address) : "memory");
    return result;
}
unsigned long m6_entry(unsigned long *address, unsigned long input) {
    return update(address, input);
}
unsigned long unrelated_entry(unsigned long input) { return input + 1; }
