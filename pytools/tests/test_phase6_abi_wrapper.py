from riscv2x86_py.abi_effects import (
    AbiValueLocationKind, SourceAbiCallBinding, SourceAbiProfile,
    SourceAbiValueLocation, TargetAbiWrapperContract, TargetAbiWrapperRegistry,
    CanonicalCallSite, build_abi_effects,
    collect_canonical_call_sites,
)

def _loc(reg):
    return SourceAbiValueLocation(AbiValueLocationKind.GPR,reg,None,64,"unsigned","scalar",True)

def _binding(**kw):
    values=dict(fragment_id="f",block_address=0x1000,operation_index=0,
        source_abi_profile=SourceAbiProfile.RV64_LP64,direct_target_id="crc.u64",
        source_semantic_contract_id="crc.semantic",source_semantic_version="1",
        argument_operand_indexes=(1,),return_operand_indexes=(0,),argument_types=("uint64_t",),return_types=("uint64_t",),
        source_argument_locations=(_loc("a1"),),source_return_locations=(_loc("a0"),),
        stack_alignment_bytes=16,pic_plt_mode="direct",tls_model="none",may_return=True,may_unwind=False,may_trap=False,memory_effect="none",binding_complete=True,provenance="test")
    values.update(kw); return SourceAbiCallBinding(**values)

def test_exact_direct_scalar_call_requires_and_resolves_versioned_contract():
    site=CanonicalCallSite(0x1000,0,True,None,("a1",),("a0",),False,True,True,True)
    effects=build_abi_effects(has_call=True,bindings=(_binding(),),call_sites=(site,))
    assert effects is not None and effects.complete and len(effects.calls)==1
    contract=TargetAbiWrapperContract("abi.crc.v1","1",SourceAbiProfile.RV64_LP64,"sysv_amd64","crc.u64","rv2x86_crc_u64",("uint64_t",),("uint64_t",),(1,),(0,),"none",True,False,("crc.h",),None,True,True,"crc.semantic")
    assert TargetAbiWrapperRegistry((contract,)).resolve(effects,"sysv_amd64") == contract

def test_missing_or_nonreturning_sidecar_fails_closed():
    assert not build_abi_effects(has_call=True,bindings=(),call_sites=()).complete
    site=CanonicalCallSite(0x1000,0,True,None,("a1",),("a0",),False,True,True,True)
    assert not build_abi_effects(has_call=True,bindings=(_binding(may_return=False),),call_sites=(site,)).complete

def test_call_site_and_sidecar_location_mismatch_fails_closed():
    site=CanonicalCallSite(0x1000,1,True,None,("a1",),("a0",),False,True,True,True)
    effects=build_abi_effects(has_call=True,bindings=(_binding(),),call_sites=(site,))
    assert not effects.complete
    assert "abi-call.call-site-mismatch" in effects.missing_fact_codes

def test_canonical_inventory_keeps_block_operation_identity():
    from riscv2x86_py.pcode_ir import Block, Op, Var, VarKind
    from riscv2x86_py.cfg import build_cfg_from_blocks
    a1=Var(VarKind.REG,"register",11,8,"a1"); a0=Var(VarKind.REG,"register",10,8,"a0")
    block=Block(0x1000,ops=[Op(0x1000,"CALL",a0,[a1])],call_targets=[0x2000])
    sites=collect_canonical_call_sites(blocks=[block],cfg=build_cfg_from_blocks([block]))
    assert sites == (CanonicalCallSite(0x1000,0,True,"8192",("a1",),("a0",),False,True,True,True),)
