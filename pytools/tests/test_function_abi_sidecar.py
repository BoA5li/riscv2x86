from riscv2x86_py.function_abi_sidecar import FUNCTION_ABI_SIDECAR_SCHEMA, function_abi_sidecar_from_dict

def _value(t,w,s,kind,register=None,offset=None):
    return {"typeId":t,"widthBits":w,"signedness":s,"locationKind":kind,"register":register,"stackOffsetBytes":offset,"complete":True}

def _sidecar():
    return {"schemaVersion":FUNCTION_ABI_SIDECAR_SCHEMA,"compilerVersion":"clang-10","targetTriple":"riscv64-unknown-linux-gnu","provenance":"compiler-plugin.v1","functions":[{"functionId":"f","sourceAbiProfile":"rv64-lp64","entryArguments":[_value("u64",64,"unsigned","gpr","a0")],"returnValues":[_value("u64",64,"unsigned","gpr","a0")],"variadicOrAggregateAbi":False,"picPltMode":"direct","tlsModel":"none","unwindEnabled":False,"exceptionModel":"none","complete":True,"missingFactCodes":[]}]}

def test_accepts_restricted_rv64_scalar_function_abi():
    facts=function_abi_sidecar_from_dict(_sidecar()).for_function("f")
    assert facts and facts.source_abi_profile=="rv64-lp64" and facts.entry_arguments[0].register=="a0"

def test_rejects_variadic_and_non_scalar_abi():
    x=_sidecar(); x["functions"][0]["variadicOrAggregateAbi"]=True
    try: function_abi_sidecar_from_dict(x)
    except ValueError as exc: assert "variadic" in str(exc)
    else: raise AssertionError("variadic ABI must fail closed")
    x=_sidecar(); x["functions"][0]["entryArguments"][0]["typeId"]="aggregate"
    try: function_abi_sidecar_from_dict(x)
    except ValueError: pass
    else: raise AssertionError("aggregate ABI must fail closed")


def test_accepts_amd64_scalar_profile_only_with_matching_triple():
    import pytest
    x=_sidecar();x['targetTriple']='x86_64-unknown-linux-gnu'
    function=x['functions'][0];function['sourceAbiProfile']='sysv-amd64'
    function['entryArguments'][0]['register']='rdi';function['returnValues'][0]['register']='rax'
    assert function_abi_sidecar_from_dict(x).for_function('f').source_abi_profile=='sysv-amd64'
    x['targetTriple']='riscv64-linux-gnu'
    with pytest.raises(ValueError,match='target triple mismatch'):function_abi_sidecar_from_dict(x)


def test_truthy_strings_and_wrong_integer_width_do_not_become_complete():
    from copy import deepcopy
    import pytest
    for field,value in [('complete','false'),('widthBits',32),('signedness','signed'),('widthBits',True)]:
        x=_sidecar();x['functions'][0]['entryArguments'][0][field]=value
        with pytest.raises(ValueError):function_abi_sidecar_from_dict(x)
    x=_sidecar();x['functions'][0]['complete']='true'
    with pytest.raises(ValueError,match='boolean'):function_abi_sidecar_from_dict(x)
