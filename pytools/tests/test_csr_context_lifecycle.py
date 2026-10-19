from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.parametrize('mode',['missing','nested','wrong_unbind','threads'])
def test_checked_context_lifecycle_and_thread_isolation(tmp_path,mode):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native ABI execution requires gcc')
    root=Path(__file__).resolve().parents[2]
    prefix='#include "riscv2x86_csr_runtime.h"\n#include <pthread.h>\n#include <sys/resource.h>\n'
    init='struct rv2x86_csr_context c={0}; c.version=1; c.profile=RV2X86_CSR_SCRATCH_PROFILE_V1;'
    if mode=='threads':
        body='static void *worker(void *p) {'+init+'c.values[832]=(uint64_t)(uintptr_t)p; rv2x86_csr_bind_context_v1(&c); for(int i=0;i<10000;i++) if(rv2x86_csr_bound_context_v1()!=&c || rv2x86_csr_read_checked_v1(&c,832)!=(uint64_t)(uintptr_t)p) return (void*)1; rv2x86_csr_unbind_context_v1(&c); return 0;}\nint main(void){pthread_t a,b; void *x,*y; if(pthread_create(&a,0,worker,(void*)3)||pthread_create(&b,0,worker,(void*)5)) return 2; pthread_join(a,&x);pthread_join(b,&y);return x!=0||y!=0;}'
    else:
        action={'missing':'rv2x86_csr_bound_context_v1();',
            'nested':'rv2x86_csr_bind_context_v1(&c);rv2x86_csr_bind_context_v1(&c);',
            'wrong_unbind':'struct rv2x86_csr_context d=c;rv2x86_csr_bind_context_v1(&c);rv2x86_csr_unbind_context_v1(&d);'}[mode]
        body='int main(void){struct rlimit lim={0,0};setrlimit(RLIMIT_CORE,&lim);'+(init if mode!='missing' else '')+action+'return 0;}'
    source=tmp_path/'context.c';binary=tmp_path/'context';source.write_text(prefix+body)
    built=subprocess.run([gcc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',
        '-I'+str(root/'runtime/include'),str(source),str(root/'runtime/riscv2x86_csr_runtime.c'),'-o',str(binary)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    result=subprocess.run([str(binary)])
    assert result.returncode==(0 if mode=='threads' else -6)
