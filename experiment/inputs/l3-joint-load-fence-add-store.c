#include <stdint.h>

uint64_t rv2x86_probe_joint_fenced_update(uint64_t *address, uint64_t input) {
    uint64_t loaded, result;
    __asm__ volatile("ld %0,8(%1)"
                     : "=r"(loaded) : "r"(address) : "memory");
    __asm__ volatile("fence rw,rw" ::: "memory");
    __asm__ volatile("add %0,%1,%2"
                     : "=r"(result) : "r"(loaded), "r"(input) : "cc");
    __asm__ volatile("sd %0,16(%1)"
                     : : "r"(result), "r"(address) : "memory");
    return result;
}
