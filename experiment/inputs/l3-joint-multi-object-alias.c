#include <stdint.h>

uint64_t rv2x86_probe_multi_object(uint64_t *address,
                                 uint64_t *destination,
                                 uint64_t input) {
    uint64_t loaded, result, final_value;
    __asm__ volatile("ld %0,8(%1)"
                     : "=r"(loaded) : "r"(address) : "memory");
    __asm__ volatile("add %0,%1,%2"
                     : "=r"(result) : "r"(loaded), "r"(input) : "cc");
    __asm__ volatile("sd %0,8(%1)"
                     : : "r"(result), "r"(destination) : "memory");
    __asm__ volatile("fence rw,rw" ::: "memory");
    __asm__ volatile("ld %0,8(%1)"
                     : "=r"(final_value) : "r"(address) : "memory");
    return final_value;
}
