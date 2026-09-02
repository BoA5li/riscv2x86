"""Phase-8 external CSR runner contract for Spike/QEMU and x86 runtime."""
from __future__ import annotations
from dataclasses import dataclass
import json,subprocess
from hashlib import sha256
@dataclass(frozen=True)
class CsrRunnerSpec:
 command:tuple[str,...]; runner_kind:str; runtime_version:str; source_profile:str; xlen:int
@dataclass(frozen=True)
class CsrRunnerResult:
 observation:dict|None; identity:str; reason_codes:tuple[str,...]=()
def run_csr_observation(spec:CsrRunnerSpec,*,initial_state:dict,timeout_seconds:int=30)->CsrRunnerResult:
 if spec.runner_kind not in {"spike","qemu","x86-logical-runtime"} or spec.xlen not in {32,64}:return CsrRunnerResult(None,"",("csr-p8.runner-spec-invalid",))
 try:p=subprocess.run(spec.command,input=json.dumps({"initialState":initial_state,"runtimeVersion":spec.runtime_version,"profile":spec.source_profile}),text=True,capture_output=True,timeout=timeout_seconds,check=False)
 except (OSError,subprocess.TimeoutExpired):return CsrRunnerResult(None,"",("csr-p8.runner-unavailable",))
 if p.returncode:return CsrRunnerResult(None,"",("csr-p8.runner-failed",))
 try:o=json.loads(p.stdout)
 except json.JSONDecodeError:return CsrRunnerResult(None,"",("csr-p8.observation-json-invalid",))
 if not isinstance(o,dict) or o.get("runtimeVersion")!=spec.runtime_version or o.get("profile")!=spec.source_profile:return CsrRunnerResult(None,"",("csr-p8.observation-version-profile-mismatch",))
 required={"csrFields","privilegeMode","trap","continuation","memory","interrupt","mmuTlb","termination","outputs","status","externalEvents","ignoredState"}
 if not required.issubset(o):return CsrRunnerResult(None,"",("csr-p8.observation-schema-incomplete",))
 return CsrRunnerResult(o,"csr-p8:"+sha256(json.dumps(o,sort_keys=True,separators=(",",":" )).encode()).hexdigest())
def validate_csr_engineering_matrix(*,compiler:str,optimization:str,sanitizer:str,xlen:int,proof_identity:str)->tuple[bool,str]:
 return (compiler in {"gcc","clang"} and optimization in {"-O0","-O2","-O3"} and sanitizer in {"none","asan","ubsan"} and xlen in {32,64} and bool(proof_identity),"" if compiler in {"gcc","clang"} and optimization in {"-O0","-O2","-O3"} and sanitizer in {"none","asan","ubsan"} and xlen in {32,64} and bool(proof_identity) else "csr-p8.matrix-invalid")
