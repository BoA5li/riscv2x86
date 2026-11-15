# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Dict, Optional, Tuple
from .ghidra_configuration import resolve_install_dir, GhidraConfigurationError


class GhidraPythonRunError(RuntimeError):
    """support/pythonRun 调用失败或返回无效数据。"""


@dataclass(frozen=True)
class PythonRunRegisterNameResolver:
    """
    一个由 support/pythonRun + Ghidra Language API 生成的
    authoritative register resolver。

    该 resolver 在 CPython 中运行，但 register identity 数据
    来自真实 Ghidra Language。
    """

    names: Dict[Tuple[str, int, int], str]
    registers: tuple = ()
    language_id: str = ''
    big_endian: bool | None = None
    installation_dir: str | None = None
    query_evidence: dict | None = None

    def register_read_view_for_varnode(self, *, space, offset, size):
        from .register_views import database_read_view
        return database_read_view(self.registers,space=space,offset=offset,size=size,
            language_id=self.language_id,big_endian=self.big_endian)

    def register_name_for_varnode(
        self,
        *,
        space: str,
        offset: int,
        size: int,
    ) -> Optional[str]:
        return self.names.get(
            (space.lower(), int(offset), int(size))
        )


def _default_ghidra_install_dir() -> Path:
    try:return resolve_install_dir()
    except GhidraConfigurationError as exc:raise GhidraPythonRunError(str(exc)) from exc


def _default_python_run_path() -> Path:
    return _default_ghidra_install_dir() / "support" / "pythonRun"


def _default_register_query_script() -> Path:
    return Path(__file__).resolve().parents[2] / "test/minimal/backend_test/riscv_register_query.py"

def riscv_language_id_for_xlen(xlen: int) -> str:
    if xlen == 32:
        return "RISCV:LE:32:default"

    if xlen == 64:
        return "RISCV:LE:64:default"

    raise GhidraPythonRunError(
        f"Unsupported RISC-V XLEN: {xlen}; expected 32 or 64"
    )

def load_riscv64_register_resolver_via_pythonrun(
    *,
    python_run: Optional[Path] = None,
    query_script: Optional[Path] = None,
    ghidra_install_dir: Optional[str] = None,
    evidence_directory: Optional[Path] = None,
    environment: Optional[dict] = None,
    timeout: int = 60,
) -> PythonRunRegisterNameResolver:
    """
    使用 Ghidra support/pythonRun 获取 RISCV:LE:64:default
    的真实寄存器定义，并在 CPython 中构造 resolver。
    """

    if type(timeout) is not int or not 1<=timeout<=86400:raise GhidraPythonRunError('GHIDRA_QUERY_TIMEOUT_INVALID')
    selected_dir=None
    if python_run is None or ghidra_install_dir is not None:
        try:selected_dir=resolve_install_dir(ghidra_install_dir)
        except GhidraConfigurationError as exc:raise GhidraPythonRunError(str(exc)) from exc
    if python_run is None:python_run=selected_dir/'support/pythonRun'
    else:
        python_run=Path(python_run).resolve()
        if selected_dir is not None and python_run!=(selected_dir/'support/pythonRun').resolve():
            raise GhidraPythonRunError('GHIDRA_QUERY_INSTALLATION_CONFLICT')

    query_script = (
        query_script
        or _default_register_query_script()
    )

    if not python_run.is_file():
        raise GhidraPythonRunError(
            "Ghidra support/pythonRun not found: "
            f"{python_run}. "
            "Set GHIDRA_INSTALL_DIR correctly."
        )

    if not os.access(python_run, os.X_OK):
        raise GhidraPythonRunError(
            f"Ghidra support/pythonRun is not executable: {python_run}"
        )

    if not query_script.is_file():
        raise GhidraPythonRunError(
            f"Ghidra register query script not found: {query_script}"
        )

    from .project_compile_context import digest
    from .project_build_records import identity
    python_run=python_run.resolve(strict=True);query_script=query_script.resolve(strict=True)
    tools={str(p):digest(p) for p in (python_run,query_script)}
    evidence={'schemaVersion':'riscv2x86.ghidra-register-query.v1',
        'installationDirectory':str(selected_dir) if selected_dir is not None else None,
        'command':[str(python_run),str(query_script)],'tools':tools,
        'timeoutSeconds':timeout,'environment':environment,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    directory=Path(evidence_directory).resolve() if evidence_directory is not None else None
    if directory is not None:directory.mkdir(parents=True,exist_ok=False)

    # Reuse the existing bounded process-group driver. Killing only pythonRun
    # may leave its JVM or descendants running after a timeout.
    from .native_experiment_driver import command as bounded_command
    from types import SimpleNamespace
    with tempfile.TemporaryDirectory(prefix='rv2x86-ghidra-query-') as temporary:
        code,reason=bounded_command([str(python_run),str(query_script)],Path.cwd(),
            dict(os.environ) if environment is None else environment,temporary,timeout,8*1024*1024)
        stdout=(Path(temporary)/'stdout.log').read_text()
        stderr=(Path(temporary)/'stderr.log').read_text()
    completed=SimpleNamespace(returncode=code,stdout=stdout,stderr=stderr)
    if directory is not None:
        (directory/'stdout.log').write_text(completed.stdout)
        (directory/'stderr.log').write_text(completed.stderr)
    evidence.update(returnCode=completed.returncode,failureReason=reason,maxLogBytes=8*1024*1024,
        stdoutDigest='sha256:'+sha256(completed.stdout.encode()).hexdigest(),
        stderrDigest='sha256:'+sha256(completed.stderr.encode()).hexdigest())
    if directory is not None:
        (directory/'query.json').write_text(json.dumps(dict(evidence,queryIdentity=identity(evidence)),indent=2)+'\n')
    if any(digest(p)!=sha for p,sha in tools.items()):raise GhidraPythonRunError('GHIDRA_QUERY_TOOL_CHANGED')
    if reason is not None:raise GhidraPythonRunError('GHIDRA_QUERY_'+reason)

    if completed.returncode != 0:
        raise GhidraPythonRunError(
            "support/pythonRun failed.\n"
            f"command: {python_run} {query_script}\n"
            f"returncode: {completed.returncode}\n"
            f"stdout raw:\n{repr(completed.stdout)}\n"
            f"stderr:\n{completed.stderr}"
        )

    parsed=parse_register_query_output(completed.stdout)
    return replace(parsed,installation_dir=str(selected_dir) if selected_dir is not None else None,
                   query_evidence=dict(evidence,queryIdentity=identity(evidence)))


def parse_register_query_output(raw_stdout):
    """Same strict response consumer for acquisition and stored-evidence checks."""
    if not isinstance(raw_stdout,str) or len(raw_stdout.encode())>8*1024*1024:
        raise GhidraPythonRunError('GHIDRA_QUERY_OUTPUT_INVALID_OR_OVER_BUDGET')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise GhidraPythonRunError('GHIDRA_QUERY_DUPLICATE_JSON_KEY:'+key)
            result[key]=value
        return result
    def finite(value):raise GhidraPythonRunError('GHIDRA_QUERY_NONFINITE_JSON:'+value)
    decoder=json.JSONDecoder(object_pairs_hook=unique,parse_constant=finite)
    position=0;responses=[]
    while True:
        start=raw_stdout.find('{',position)
        if start<0:break
        try:record,end=decoder.raw_decode(raw_stdout,start)
        except json.JSONDecodeError:
            position=start+1;continue
        position=end
        if isinstance(record,dict) and 'ok' in record and 'language_id' in record:responses.append(record)
    if len(responses)!=1:raise GhidraPythonRunError('GHIDRA_QUERY_RESPONSE_MISSING_OR_AMBIGUOUS')
    data=responses[0]

    if data.get("ok") is not True:
        raise GhidraPythonRunError(
            f"Ghidra query returned failure: {data}"
        )
    if data.get('schemaVersion') not in (None,'riscv2x86.ghidra-register-database.v2'):
        raise GhidraPythonRunError('GHIDRA_REGISTER_DATABASE_SCHEMA_UNSUPPORTED')

    if data.get("language_id") != "RISCV:LE:64:default":
        raise GhidraPythonRunError(
            "unexpected Ghidra language ID: "
            f"{data.get('language_id')!r}"
        )

    names = {}

    registers=data.get('registers')
    if not isinstance(registers,list) or not registers:raise GhidraPythonRunError('GHIDRA_REGISTER_DATABASE_REQUIRED')
    seen={}
    for register in registers:
        if not isinstance(register,dict):raise GhidraPythonRunError('GHIDRA_REGISTER_RECORD_INVALID')
        name=register.get('name');offset=register.get('offset');size=register.get('size')
        if (not isinstance(name,str) or not name.strip() or '\0' in name or type(offset) is not int or offset<0
                or type(size) is not int or size<=0):raise GhidraPythonRunError('GHIDRA_REGISTER_LOCATION_INVALID')
        if name in seen and seen[name]!=(offset,size):raise GhidraPythonRunError('GHIDRA_REGISTER_NAME_CONFLICT')
        seen[name]=(offset,size)

        key = ("register", offset, size)

        names.setdefault(key, name)

    if not names:
        raise GhidraPythonRunError(
            "Ghidra query returned no usable RISC-V registers"
        )

    versioned = data.get('schemaVersion') == 'riscv2x86.ghidra-register-database.v2'
    if versioned:
        if data.get('bigEndian') is not False:raise GhidraPythonRunError('GHIDRA_RISCV_LE_ENDIANNESS_REQUIRED')
        for register in registers:
            if (type(register.get('bitLength')) is not int or not 0<register['bitLength']<=8*register['size']
                    or type(register.get('isProcessorContext')) is not bool
                    or not isinstance(register.get('baseName'),str) or not register['baseName']
                    or type(register.get('baseOffset')) is not int or register['baseOffset']<0
                    or type(register.get('baseSize')) is not int or register['baseSize']<=0):
                raise GhidraPythonRunError('GHIDRA_REGISTER_VIEW_METADATA_REQUIRED')
        if not any(r['bitLength']==64 and r['size']==8 and not r['isProcessorContext'] for r in registers):
            raise GhidraPythonRunError('GHIDRA_RV64_REGISTER_WIDTH_REQUIRED')
    return PythonRunRegisterNameResolver(names=names,
        registers=tuple(data['registers']) if versioned else (),
        language_id=data['language_id'],big_endian=data.get('bigEndian') if versioned else None)



def load_riscv_register_resolver_via_pythonrun(
    *,
    xlen: int,
    ghidra_install_dir: Optional[str] = None,
    language_id: Optional[str] = None,
) -> PythonRunRegisterNameResolver:

    selected_language_id = (
        language_id
        or riscv_language_id_for_xlen(xlen)
    )

    if xlen != 64:
        raise GhidraPythonRunError(
            "The current pythonRun register resolver implementation "
            f"supports RV64 only; got xlen={xlen}, "
            f"language_id={selected_language_id!r}"
        )

    if (
        language_id is not None
        and language_id != "RISCV:LE:64:default"
    ):
        raise GhidraPythonRunError(
            "The current pythonRun resolver loader does not yet support "
            f"custom language_id={language_id!r}"
        )

    return load_riscv64_register_resolver_via_pythonrun(
        ghidra_install_dir=ghidra_install_dir
    )
