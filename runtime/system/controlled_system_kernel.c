/* QEMU 7.2 virt, one hart, -bios none. Entire kernel compiled RV64I+Zicsr.
 * CLINT MTIP is already pending for WFI. This is not a future-event or liveness
 * test. All transport memory is private; no ordinary program memory is exposed. */
typedef unsigned long u64;
typedef unsigned int u32;
static volatile unsigned count, events[8];
static volatile u64 trap_pc;
extern void __rv2x86_probe(void);
static void put(char c) {
    volatile unsigned char *uart=(volatile unsigned char *)0x10000000UL;
    while (!(uart[5] & 0x20)) { }
    uart[0]=(unsigned char)c;
}
static void text(const char *s) { while (*s) put(*s++); }
static void number(u64 n) {
    /* Hex-free decimal division would need compiler runtime in RV64I. The
       observed fields fit 16 bits, so use bounded repeated subtraction. */
    const u64 powers[5]={10000,1000,100,10,1}; unsigned i, started=0;
    for (i=0;i<5;i++) { unsigned digit=0; while(n>=powers[i]){n-=powers[i];digit++;}
        if(digit||started||i==4){put((char)('0'+digit));started=1;} }
}
static void event(unsigned e) { if(count<8) events[count++]=e; }
static void finish(unsigned ok) {
    *(volatile u32 *)0x100000UL=ok ? 0x5555 : 0x3333;
    for (;;) { __asm__ volatile("wfi"); }
}
void __rv2x86_kernel_trap(void) {
    u64 cause, pc;
    __asm__ volatile("csrr %0, mcause":"=r"(cause));
    __asm__ volatile("csrr %0, mepc":"=r"(pc));
    if (__RV2X86_OPERATION!=1 || cause!=11 || *(volatile u32 *)pc!=0x00000073) finish(0);
    trap_pc=pc; event(2); pc+=4;
    __asm__ volatile("csrw mepc, %0"::"r"(pc):"memory");
}
void __rv2x86_kernel_main(void) {
    u64 status,cause,epc,mie,mip,tval; unsigned i;
    __asm__ volatile("csrw mie, zero; csrw mcause, zero; csrw mepc, zero; csrw mtval, zero; csrw medeleg, zero; csrw mideleg, zero":::"memory");
    *(volatile u32 *)0x2000000UL=0;
    *(volatile u64 *)0x2004000UL=~(u64)0;
    do { __asm__ volatile("csrr %0, mip":"=r"(mip)); } while(mip&128);
    status=0x1800;
    __asm__ volatile("csrw mstatus, %0"::"r"(status):"memory");
    if (__RV2X86_OPERATION==2) {
        *(volatile u64 *)0x2004000UL=0;
        mie=128; __asm__ volatile("csrw mie, %0"::"r"(mie):"memory");
        do { __asm__ volatile("csrr %0, mip":"=r"(mip)); } while(!(mip&128));
    }
    event(__RV2X86_OPERATION==1 ? 1 : 4);
    __rv2x86_probe();
    event(__RV2X86_OPERATION==1 ? 3 : 5);
    __asm__ volatile("csrr %0, mstatus":"=r"(status));
    __asm__ volatile("csrr %0, mcause":"=r"(cause));
    __asm__ volatile("csrr %0, mepc":"=r"(epc));
    __asm__ volatile("csrr %0, mie":"=r"(mie));
    __asm__ volatile("csrr %0, mip":"=r"(mip));
    __asm__ volatile("csrr %0, mtval":"=r"(tval));
    text("RV2X86_SYSTEM:{\"operation\":");number(__RV2X86_OPERATION);
    text(",\"events\":[");for(i=0;i<count;i++){if(i)put(',');number(events[i]);}
    text("],\"mstatus\":");number(status&0x1888);
    text(",\"mcause\":");number(cause);
    text(",\"mtval\":");number(tval);
    text(",\"mepcNext\":");number(trap_pc && epc==trap_pc+4 ? 1 : 0);
    text(",\"mie\":");number(mie&128);
    text(",\"mip\":");number(mip&128);
    text(",\"completed\":1}\n");finish(1);
}
