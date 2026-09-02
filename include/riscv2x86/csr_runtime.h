#ifndef RISCV2X86_CSR_RUNTIME_H
#define RISCV2X86_CSR_RUNTIME_H
#include <stdbool.h>
#include <stdint.h>
enum rv2x86_counter_domain { RV2X86_COUNTER_MONOTONIC_TIME, RV2X86_COUNTER_CYCLE_RELATION, RV2X86_COUNTER_EMULATOR_INSN };
enum rv2x86_overflow_policy { RV2X86_OVERFLOW_WRAP, RV2X86_OVERFLOW_SATURATE, RV2X86_OVERFLOW_TRAP };
enum rv2x86_csr_result { RV2X86_CSR_OK, RV2X86_CSR_DENIED, RV2X86_CSR_WARL_REJECTED, RV2X86_CSR_UNSUPPORTED };
struct rv2x86_counter_context { enum rv2x86_counter_domain domain; uint64_t frequency_hz,resolution_ns; bool per_thread,migration_safe,serialized,virtualized; enum rv2x86_overflow_policy overflow_policy; };
struct rv2x86_csr_descriptor { uint16_t address; uint64_t writable_mask; uint64_t warl_mask; bool readable,writable; };
struct rv2x86_csr_context { const char *runtime_version; uint64_t lifetime_id; const struct rv2x86_csr_descriptor *descriptors; uint32_t descriptor_count; uint64_t values[4096]; };
uint64_t rv2x86_read_time(const struct rv2x86_counter_context *, enum rv2x86_csr_result *);
enum rv2x86_csr_result rv2x86_csr_read(const struct rv2x86_csr_context *,uint16_t,uint64_t *);
enum rv2x86_csr_result rv2x86_csr_write(struct rv2x86_csr_context *,uint16_t,uint64_t,uint64_t *);
enum rv2x86_csr_result rv2x86_csr_set_bits(struct rv2x86_csr_context *,uint16_t,uint64_t,uint64_t *);
enum rv2x86_csr_result rv2x86_csr_clear_bits(struct rv2x86_csr_context *,uint16_t,uint64_t,uint64_t *);
#endif
