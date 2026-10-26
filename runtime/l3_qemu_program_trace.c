/* SPDX-License-Identifier: GPL-2.0-or-later
 * API-v1 ordered, disjoint compiler regions in one whole-function execution.
 * No register values, timing or concurrency claims are generated here.
 */
#include <qemu/qemu-plugin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static uint64_t starts[16], ends[16], count, next_region, calls, accesses;
static int active, invalid;
static FILE *out;
static void instruction(unsigned int cpu, void *data)
{
    uint64_t pc=(uint64_t)(uintptr_t)data;
    if(cpu) invalid=1;
    if(active && pc==ends[next_region]) {
        fprintf(out,"E %"PRIu64" %"PRIu64" %"PRIx64"\n",calls,next_region,pc);
        active=0;
        if(++next_region==count) {next_region=0;calls++;}
    }
    for(uint64_t i=0;i<count;i++) if(pc==starts[i]) {
        if(active || i!=next_region || calls>=32) {
            invalid=1;fprintf(out,"U %"PRIu64" %"PRIu64" %"PRIx64"\n",calls,i,pc);return;
        }
        active=1;fprintf(out,"B %"PRIu64" %"PRIu64" %"PRIx64"\n",calls,i,pc);
    }
    if(active && (pc<starts[next_region] || pc>=ends[next_region])) {
        invalid=1;active=0;fprintf(out,"U %"PRIu64" %"PRIu64" %"PRIx64"\n",calls,next_region,pc);
    }
}
static void memory(unsigned int cpu,qemu_plugin_meminfo_t info,uint64_t address,void *data)
{
    uint64_t pc=(uint64_t)(uintptr_t)data;unsigned int shift=qemu_plugin_mem_size_shift(info);
    if(cpu || !active || shift>6 || accesses>=4096) {invalid=1;return;}
    fprintf(out,"M %"PRIu64" %"PRIu64" %"PRIu64" %"PRIx64" %"PRIx64" %u %c\n",
        accesses++,calls,next_region,pc,address,1u<<shift,qemu_plugin_mem_is_store(info)?'W':'R');
}
static void translate(qemu_plugin_id_t id,struct qemu_plugin_tb *tb)
{
    (void)id;
    for(size_t i=0;i<qemu_plugin_tb_n_insns(tb);i++) {
        struct qemu_plugin_insn *insn=qemu_plugin_tb_get_insn(tb,i);uint64_t pc=qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn,instruction,QEMU_PLUGIN_CB_NO_REGS,(void*)(uintptr_t)pc);
        for(uint64_t j=0;j<count;j++) if(pc>=starts[j] && pc<ends[j])
            qemu_plugin_register_vcpu_mem_cb(insn,memory,QEMU_PLUGIN_CB_NO_REGS,QEMU_PLUGIN_MEM_RW,(void*)(uintptr_t)pc);
    }
}
static void finish(qemu_plugin_id_t id,void *data)
{
    (void)id;(void)data;
    fprintf(out,"F %"PRIu64" %"PRIu64" %"PRIu64" %d\n",calls,next_region,accesses,invalid||active);
    fclose(out);
}
static uint64_t number(const char *s)
{
    char *last;errno=0;uint64_t v=strtoull(s,&last,0);
    return errno || !*s || *last?0:v;
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,const qemu_info_t *info,int argc,char **argv)
{
    const char *path=NULL,*token=NULL,*regions=NULL;unsigned int seen=0;
    if(QEMU_PLUGIN_VERSION!=1 || !info || info->system_emulation || argc!=3)return -1;
    for(int i=0;i<argc;i++) {
        unsigned int bit=0;
        if(!strncmp(argv[i],"regions=",8)){bit=1;regions=argv[i]+8;}
        else if(!strncmp(argv[i],"output=",7)){bit=2;path=argv[i]+7;}
        else if(!strncmp(argv[i],"token=",6)){bit=4;token=argv[i]+6;}
        else return -1;
        if(seen&bit)return -1;
        seen|=bit;
    }
    if(seen!=7 || !*path || strlen(token)!=64)return -1;
    for(size_t i=0;i<64;i++)if(!((token[i]>='0'&&token[i]<='9')||(token[i]>='a'&&token[i]<='f')))return -1;
    char *copy=strdup(regions),*save=NULL,*p;if(!copy)return -1;
    for(p=strtok_r(copy,";",&save);p;p=strtok_r(NULL,";",&save)) {
        char *colon=strchr(p,':');if(count>=16 || !colon){free(copy);return -1;}
        *colon=0;starts[count]=number(p);ends[count]=number(colon+1);
        if(!starts[count] || ends[count]<=starts[count] || (count && starts[count]<ends[count-1])){free(copy);return -1;}
        count++;
    }
    free(copy);if(count<2)return -1;
    out=fopen(path,"wx");if(!out)return -1;
    fprintf(out,"H 3 %s %s\n",token,info->target_name);
    qemu_plugin_register_vcpu_tb_trans_cb(id,translate);qemu_plugin_register_atexit_cb(id,finish,NULL);return 0;
}
