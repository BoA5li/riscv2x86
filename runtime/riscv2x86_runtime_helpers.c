#include "riscv2x86_runtime_helpers.h"

uint64_t riscv2x86_rt_rv64_mulhu_u64(uint64_t lhs, uint64_t rhs) {
    return (uint64_t)(((__uint128_t)lhs * (__uint128_t)rhs) >> 64);
}
