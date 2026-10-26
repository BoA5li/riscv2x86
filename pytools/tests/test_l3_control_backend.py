"""Actual C callback execution with an API-v1 stub, not an emulator substitute."""
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py.l3_control_backend import parse_capture

HEADER=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define QEMU_PLUGIN_VERSION 1
#define QEMU_PLUGIN_EXPORT
#define QEMU_PLUGIN_CB_NO_REGS 0
#define QEMU_PLUGIN_MEM_RW 3
typedef uint64_t qemu_plugin_id_t;
typedef uint32_t qemu_plugin_meminfo_t;
typedef struct { bool system_emulation; const char *target_name; } qemu_info_t;
struct qemu_plugin_tb {int unused;};
struct qemu_plugin_insn {int unused;};
static inline size_t qemu_plugin_tb_n_insns(struct qemu_plugin_tb *tb){(void)tb;return 0;}
static inline struct qemu_plugin_insn *qemu_plugin_tb_get_insn(struct qemu_plugin_tb *tb,size_t i){(void)tb;(void)i;return NULL;}
static inline uint64_t qemu_plugin_insn_vaddr(struct qemu_plugin_insn *i){(void)i;return 0;}
static inline unsigned int qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t i){return i&63;}
static inline bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t i){return (i&256)!=0;}
static inline void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *i,void(*f)(unsigned int,void*),int flags,void *u){(void)i;(void)f;(void)flags;(void)u;}
static inline void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *i,void(*f)(unsigned int,qemu_plugin_meminfo_t,uint64_t,void*),int flags,int mode,void *u){(void)i;(void)f;(void)flags;(void)mode;(void)u;}
static inline void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t i,void(*f)(qemu_plugin_id_t,struct qemu_plugin_tb*)){(void)i;(void)f;}
static inline void qemu_plugin_register_atexit_cb(qemu_plugin_id_t i,void(*f)(qemu_plugin_id_t,void*),void *u){(void)i;(void)f;(void)u;}
'''


@pytest.mark.parametrize('scenario',['exit','memory','escape','reentry','cpu','partial'])
def test_real_plugin_callbacks_complete_paths_and_failures(tmp_path,scenario):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    header=tmp_path/'include/qemu/qemu-plugin.h';header.parent.mkdir(parents=True);header.write_text(HEADER)
    plugin=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_control_trace.c'
    src=tmp_path/'driver.c';binary=tmp_path/'driver';trace=tmp_path/'capture.log';token='a'*64
    action={'exit':'instruction(0,(void*)0x2000);',
      'memory':'memory(0,3,0x3000,(void*)0x1004);instruction(0,(void*)0x1008);',
      'escape':'instruction(0,(void*)0x3000);',
      'reentry':'instruction(0,(void*)0x1000);',
      'cpu':'instruction(1,(void*)0x2000);','partial':''}[scenario]
    src.write_text('#include "'+str(plugin)+'"\nint main(void){qemu_info_t info={false,"riscv64"};char *args[]={"start=0x1000","end=0x1008","exits=0x1008:0x2000","limit=4096","output='+str(trace)+'","token='+token+'"};if(qemu_plugin_install(1,&info,6,args))return 2;instruction(0,(void*)0x1000);instruction(0,(void*)0x1004);'+action+'finish(1,NULL);return 0;}')
    result=subprocess.run([cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(header.parents[1]),str(src),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    run=subprocess.run([str(binary)],capture_output=True,text=True)
    assert run.returncode==0 and not run.stdout and not run.stderr
    region={'start':4096,'end':4104,'exits':[4104,8192]}
    if scenario in ('exit','memory'):
        observed=parse_capture(trace.read_text(),token,'riscv64',region,1)
        assert observed['paths'][0]['pcs']==[4096,4100]
        assert bool(observed['memory'])==(scenario=='memory')
    else:
        with pytest.raises(ValueError):parse_capture(trace.read_text(),token,'riscv64',region,1)
