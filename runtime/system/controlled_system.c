#include "controlled_system.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
static struct {
    unsigned operation, count, events[8];
    uint64_t mstatus, mcause, mie, mip;
    unsigned mepc_next;
} state;
void __rv2x86_system_event(unsigned event) {
    if (state.count >= 8) abort();
    state.events[state.count++] = event;
}
void __rv2x86_system_initialize(unsigned operation) {
    if (operation != 1 && operation != 2) abort();
    state.operation = operation; state.count = 0;
    state.mstatus = 0x1800; state.mcause = 0; state.mepc_next = 0;
    state.mie = operation == 2 ? 128 : 0;
    state.mip = operation == 2 ? 128 : 0;
}
void rv2x86_m_ecall_v1(void) {
    if (state.operation != 1 || state.mstatus != 0x1800 || state.mie || state.mip) abort();
    __rv2x86_system_event(2);
    /* M-mode ECALL enters M, then the registered handler advances mepc by
       four and MRET restores MIE=0, sets MPIE, and clears MPP on this U-capable
       QEMU machine. No native host trap/privilege equivalence is claimed. */
    state.mcause = 11; state.mepc_next = 1; state.mstatus = 128;
}
void rv2x86_m_wfi_pending_v1(void) {
    if (state.operation != 2 || state.mstatus != 0x1800 || !(state.mie & state.mip & 128)) abort();
    /* A locally enabled event is already pending; WFI need not stall. This
       supplies a wait hint while retaining the exact logical state. */
    __asm__ volatile("pause" ::: "memory");
}
void __rv2x86_system_finish(void) {
    unsigned i;
    printf("RV2X86_SYSTEM:{\"operation\":%u,\"events\":[", state.operation);
    for (i=0;i<state.count;i++) printf("%s%u", i ? "," : "", state.events[i]);
    printf("],\"mstatus\":%llu,\"mcause\":%llu,\"mtval\":0,\"mepcNext\":%u,\"mie\":%llu,\"mip\":%llu,\"completed\":1}\n",
        (unsigned long long)state.mstatus, (unsigned long long)state.mcause, state.mepc_next,
        (unsigned long long)state.mie, (unsigned long long)state.mip);
}
