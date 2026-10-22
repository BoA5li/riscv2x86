#ifndef RV2X86_CONTROLLED_SYSTEM_H
#define RV2X86_CONTROLLED_SYSTEM_H
/* Private transport and logical state for the explicitly selected M-mode domain.
 * Not an implementation of Linux syscall or a general x86 WFI instruction. */
void __rv2x86_system_initialize(unsigned operation);
void __rv2x86_system_event(unsigned event);
void __rv2x86_system_finish(void);
void rv2x86_m_ecall_v1(void);
void rv2x86_m_wfi_pending_v1(void);
#endif
