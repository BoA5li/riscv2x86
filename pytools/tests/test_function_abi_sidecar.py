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
