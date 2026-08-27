from riscv2x86_py.csr_spec_catalog import CsrCatalogProfile, DEFAULT_CSR_SPECIFICATION_CATALOG, PRIV_SPEC_1_12, PRIV_SPEC_1_13

def test_version_and_extension_profile_lookup_fails_closed():
    rv64=CsrCatalogProfile(PRIV_SPEC_1_12,64,("f","zicsr"))
    assert DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="fcsr",profile=rv64)
    assert DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="fcsr",profile=CsrCatalogProfile(PRIV_SPEC_1_12,64,("zicsr",))) is None
    assert DEFAULT_CSR_SPECIFICATION_CATALOG.resolve(numeric_address=0x300,profile=CsrCatalogProfile(PRIV_SPEC_1_13,64,("zicsr",))) is None

def test_rv32_rv64_layouts_and_version_documents_are_distinct():
    rv32=CsrCatalogProfile(PRIV_SPEC_1_12,32,("zicsr",)); rv64=CsrCatalogProfile(PRIV_SPEC_1_12,64,("zicsr",))
    assert DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="cycleh",profile=rv32)
    assert DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="cycleh",profile=rv64) is None
    assert next(x for x in DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="satp",profile=rv32).fields if x.field_id=="mode").bit_offset==31
    assert next(x for x in DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="satp",profile=rv64).fields if x.field_id=="mode").bit_offset==60
    assert DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="mvendorid",profile=CsrCatalogProfile(PRIV_SPEC_1_13,64,("zicsr",)))

def test_views_and_route_required_entries_are_explicit():
    profile=CsrCatalogProfile(PRIV_SPEC_1_12,64,("f","zicsr"))
    fcsr=DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="fcsr",profile=profile)
    assert {x.canonical_field_id for x in fcsr.fields}=={"riscv.fcsr.fflags","riscv.fcsr.frm"}
    mstatus=DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="mstatus",profile=profile); sstatus=DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="sstatus",profile=profile)
    assert next(x for x in mstatus.fields if x.field_id=="fs").canonical_field_id==next(x for x in sstatus.fields if x.field_id=="fs").canonical_field_id
    assert not DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="pmpcfg0",profile=profile).complete
