#define _POSIX_C_SOURCE 200809L
#include "riscv2x86_csr_runtime.h"
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include "riscv2x86_time_trace.h"
static rv2x86_system_adapter_fn adapters[5];
uint64_t rv2x86_read_time_trace_checked_v1(const struct rv2x86_counter_context *c, enum rv2x86_counter_id id) {
  if (c || id != RV2X86_COUNTER_CONTROLLED_TIME) abort();
  int saved_errno = errno;
  uint64_t value = rv2x86_time_trace_read_v1(0);
  errno = saved_errno;
  return value;
}
uint64_t riscv2x86_rt_monotonic_time_ns_v1(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
  return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
uint64_t riscv2x86_rt_tsc_ticks_v1(void) {
#if defined(__x86_64__) || defined(__i386__)
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi) : : "memory");
  return ((uint64_t)hi << 32) | (uint64_t)lo;
#else
  return 0;
#endif
}
uint64_t rv2x86_read_counter(const struct rv2x86_counter_context *c, enum rv2x86_counter_id id) {
  if (!c || id != RV2X86_COUNTER_MONOTONIC_NS) return 0;
  return riscv2x86_rt_monotonic_time_ns_v1();
}
/* Versioned fail-closed API: failure is never encoded as a counter value. */
uint64_t rv2x86_read_counter_checked_v1(const struct rv2x86_counter_context *c, enum rv2x86_counter_id id) {
  struct timespec t;
  if (!c || c->version != 1 || id != RV2X86_COUNTER_MONOTONIC_NS) abort();
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) abort();
  return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static int valid(uint16_t x) { return x < 4096; }
uint64_t rv2x86_csr_read(const struct rv2x86_csr_context *c,uint16_t x){return c&&valid(x)?c->values[x]:0;}
uint64_t rv2x86_csr_write(struct rv2x86_csr_context *c,uint16_t x,uint64_t v){uint64_t o=rv2x86_csr_read(c,x);if(c&&valid(x))c->values[x]=v;return o;}
uint64_t rv2x86_csr_set_bits(struct rv2x86_csr_context *c,uint16_t x,uint64_t v){return rv2x86_csr_write(c,x,rv2x86_csr_read(c,x)|v);}
uint64_t rv2x86_csr_clear_bits(struct rv2x86_csr_context *c,uint16_t x,uint64_t v){return rv2x86_csr_write(c,x,rv2x86_csr_read(c,x)&~v);}
int rv2x86_register_system_adapter(enum rv2x86_system_family f,rv2x86_system_adapter_fn fn){if((unsigned)f>=5||!fn)return -1;adapters[f]=fn;return 0;}
int rv2x86_call_system_adapter(enum rv2x86_system_family f,void *c,uint32_t o,uint64_t v,uint64_t *r){if((unsigned)f>=5||!adapters[f])return -1;return adapters[f](c,o,v,r);}

static void checked_scratch(const struct rv2x86_csr_context *c, uint16_t x) {
  if (!c || c->version != 1 || c->profile != RV2X86_CSR_SCRATCH_PROFILE_V1
      || (x != 0x140 && x != 0x340)) abort();
}
uint64_t rv2x86_csr_read_checked_v1(const struct rv2x86_csr_context *c, uint16_t x) {
  checked_scratch(c, x); return c->values[x];
}
uint64_t rv2x86_csr_write_checked_v1(struct rv2x86_csr_context *c, uint16_t x, uint64_t v) {
  checked_scratch(c, x); uint64_t old = c->values[x]; c->values[x] = v; return old;
}
uint64_t rv2x86_csr_set_bits_checked_v1(struct rv2x86_csr_context *c, uint16_t x, uint64_t mask) {
  checked_scratch(c, x); uint64_t old = c->values[x]; c->values[x] = old | mask; return old;
}
uint64_t rv2x86_csr_clear_bits_checked_v1(struct rv2x86_csr_context *c, uint16_t x, uint64_t mask) {
  checked_scratch(c, x); uint64_t old = c->values[x]; c->values[x] = old & ~mask; return old;
}

static _Thread_local struct rv2x86_csr_context *bound_scratch_context;
void rv2x86_csr_bind_context_v1(struct rv2x86_csr_context *c) {
  checked_scratch(c, 0x340);
  if (bound_scratch_context) abort();
  bound_scratch_context = c;
}
void rv2x86_csr_unbind_context_v1(struct rv2x86_csr_context *c) {
  if (!c || bound_scratch_context != c) abort();
  bound_scratch_context = NULL;
}
struct rv2x86_csr_context *rv2x86_csr_bound_context_v1(void) {
  checked_scratch(bound_scratch_context, 0x340);
  return bound_scratch_context;
}
