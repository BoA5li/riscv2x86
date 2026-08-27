#include "riscv2x86_csr_runtime.h"
#include <time.h>
static rv2x86_system_adapter_fn adapters[5];
uint64_t rv2x86_read_counter(const struct rv2x86_counter_context *c, enum rv2x86_counter_id id) {
  struct timespec t; if (!c || id != RV2X86_COUNTER_MONOTONIC_NS) return 0;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
  return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static int valid(uint16_t x) { return x < 4096; }
uint64_t rv2x86_csr_read(const struct rv2x86_csr_context *c,uint16_t x){return c&&valid(x)?c->values[x]:0;}
uint64_t rv2x86_csr_write(struct rv2x86_csr_context *c,uint16_t x,uint64_t v){uint64_t o=rv2x86_csr_read(c,x);if(c&&valid(x))c->values[x]=v;return o;}
uint64_t rv2x86_csr_set_bits(struct rv2x86_csr_context *c,uint16_t x,uint64_t v){return rv2x86_csr_write(c,x,rv2x86_csr_read(c,x)|v);}
uint64_t rv2x86_csr_clear_bits(struct rv2x86_csr_context *c,uint16_t x,uint64_t v){return rv2x86_csr_write(c,x,rv2x86_csr_read(c,x)&~v);}
int rv2x86_register_system_adapter(enum rv2x86_system_family f,rv2x86_system_adapter_fn fn){if((unsigned)f>=5||!fn)return -1;adapters[f]=fn;return 0;}
int rv2x86_call_system_adapter(enum rv2x86_system_family f,void *c,uint32_t o,uint64_t v,uint64_t *r){if((unsigned)f>=5||!adapters[f])return -1;return adapters[f](c,o,v,r);}
