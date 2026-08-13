#pragma once
#include <stdint.h>

/* Runtime ABI/semantic contract: riscv2x86.runtime.rv64.mulhu.u64@v1. */
uint64_t riscv2x86_rt_rv64_mulhu_u64(uint64_t lhs, uint64_t rhs);

/* Runtime ABI/semantic contract: instruction-stream-sync.local@v1.
 * Local-thread synchronization only; cross-thread code publication requires
 * a separately registered runtime protocol. */
void riscv2x86_rt_instruction_stream_sync_local(void);
