from riscv2x86_py.abi_effects import (
    AbiValueLocationKind, SourceAbiCallBinding, SourceAbiProfile,
    SourceAbiValueLocation, TargetAbiWrapperContract, TargetAbiWrapperRegistry,
    build_abi_effects,
)

def _loc(reg):
    return SourceAbiValueLocation(AbiValueLocationKind.GPR,reg,None,64,"unsigned","scalar",True)

def _binding(**kw):
    values=dict(fragment_id="f",block_address=0x1000,operation_index=0,
        source_abi_profile=SourceAbiProfile.RV64_LP64,direct_target_id="crc.u64",
        source_semantic_contract_id="crc.semantic",source_semantic_version="1",
        argument_operand_indexes=(1,),return_operand_indexes=(0,),argument_types=("uint64_t",),return_types=("uint64_t",),
        source_argument_locations=(_loc("a1"),),source_return_locations=(_loc("a0"),),
        stack_alignment_bytes=16,pic_plt_mode="direct",tls_model="none",may_return=True,may_unwind=False,memory_effect="none",binding_complete=True,provenance="test")
    values.update(kw); return SourceAbiCallBinding(**values)

def test_exact_direct_scalar_call_requires_and_resolves_versioned_contract():
    effects=build_abi_effects(has_call=True,bindings=(_binding(),))
    assert effects is not None and effects.complete and len(effects.calls)==1
    contract=TargetAbiWrapperContract("abi.crc.v1","1",SourceAbiProfile.RV64_LP64,"sysv_amd64","crc.u64","rv2x86_crc_u64",("uint64_t",),("uint64_t",),(1,),(0,),"none",True,False,("crc.h",),None,True,True,"crc.semantic")
    assert TargetAbiWrapperRegistry((contract,)).resolve(effects,"sysv_amd64") == contract

def test_missing_or_nonreturning_sidecar_fails_closed():
    assert not build_abi_effects(has_call=True,bindings=()).complete
    assert not build_abi_effects(has_call=True,bindings=(_binding(may_return=False),)).complete
