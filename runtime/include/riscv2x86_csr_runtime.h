#ifndef RISCV2X86_CSR_RUNTIME_H
#define RISCV2X86_CSR_RUNTIME_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum rv2x86_counter_id { RV2X86_COUNTER_MONOTONIC_NS, RV2X86_COUNTER_LOGICAL_CYCLE, RV2X86_COUNTER_INSTRET };
struct rv2x86_counter_context { uint32_t version; uint32_t flags; uint64_t frequency_hz; uint64_t resolution_ns; uint8_t per_thread, migration_safe, serialized, virtualized; };
/* Domain is declared by context; this function never equates RDTSC with cycle. */
uint64_t rv2x86_read_counter(const struct rv2x86_counter_context *, enum rv2x86_counter_id);
struct rv2x86_csr_context { uint32_t version; uint32_t profile; uint64_t values[4096]; };
uint64_t rv2x86_csr_read(const struct rv2x86_csr_context *, uint16_t);
uint64_t rv2x86_csr_write(struct rv2x86_csr_context *, uint16_t, uint64_t);
uint64_t rv2x86_csr_set_bits(struct rv2x86_csr_context *, uint16_t, uint64_t);
uint64_t rv2x86_csr_clear_bits(struct rv2x86_csr_context *, uint16_t, uint64_t);
enum rv2x86_system_family { RV2X86_SYSTEM_MMU, RV2X86_SYSTEM_INTERRUPT, RV2X86_SYSTEM_PMP, RV2X86_SYSTEM_DEBUG, RV2X86_SYSTEM_VIRTUALIZATION };
typedef int (*rv2x86_system_adapter_fn)(void *, uint32_t, uint64_t, uint64_t *);
int rv2x86_register_system_adapter(enum rv2x86_system_family, rv2x86_system_adapter_fn);
int rv2x86_call_system_adapter(enum rv2x86_system_family, void *, uint32_t, uint64_t, uint64_t *);
#ifdef __cplusplus
}
#endif
#endif
