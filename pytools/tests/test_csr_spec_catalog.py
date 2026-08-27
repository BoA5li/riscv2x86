import unittest

from riscv2x86_py.csr_spec_catalog import (
    CsrCatalogProfile, CsrFieldBehavior, DEFAULT_CSR_SPECIFICATION_CATALOG,
    PRIV_SPEC_1_12,
)


class CsrSpecificationCatalogTests(unittest.TestCase):
    def setUp(self):
        self.rv64 = CsrCatalogProfile(PRIV_SPEC_1_12, 64, ("f",))

    def test_required_initial_coverage_and_addresses(self):
        expected = {"cycle": 0xC00, "time": 0xC01, "instret": 0xC02,
            "fflags": 0x001, "frm": 0x002, "fcsr": 0x003, "mstatus": 0x300,
            "sstatus": 0x100, "mie": 0x304, "sie": 0x104, "mip": 0x344,
            "sip": 0x144, "mtvec": 0x305, "stvec": 0x105, "mepc": 0x341,
            "sepc": 0x141, "mcause": 0x342, "scause": 0x142, "mtval": 0x343,
            "stval": 0x143, "medeleg": 0x302, "mideleg": 0x303,
            "mcounteren": 0x306, "scounteren": 0x106, "satp": 0x180}
        for name, address in expected.items():
            entry = DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias=name, profile=self.rv64)
            self.assertIsNotNone(entry, name)
            self.assertEqual(address, entry.numeric_address)
            self.assertTrue(entry.complete)

    def test_version_and_extension_selection_is_fail_closed(self):
        self.assertIsNone(DEFAULT_CSR_SPECIFICATION_CATALOG.resolve(numeric_address=0x300, profile=CsrCatalogProfile("riscv-privileged-1.13", 64, ("f",))))
        self.assertIsNone(DEFAULT_CSR_SPECIFICATION_CATALOG.resolve(numeric_address=0x003, profile=CsrCatalogProfile(PRIV_SPEC_1_12, 64, ())))
        self.assertIsNotNone(DEFAULT_CSR_SPECIFICATION_CATALOG.resolve(numeric_address=0x003, profile=self.rv64))

    def test_alias_and_shared_fcsr_fields_are_explicit(self):
        fcsr = DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="riscv.csr.fcsr", profile=self.rv64)
        self.assertEqual({"fflags", "frm"}, {field.field_id for field in fcsr.fields})
        self.assertEqual(CsrFieldBehavior.WARL, next(field for field in fcsr.fields if field.field_id == "frm").behavior)

    def test_satp_has_warl_fields_and_root_change_effect(self):
        satp = DEFAULT_CSR_SPECIFICATION_CATALOG.resolve_id(csr_id_or_alias="satp", profile=self.rv64)
        self.assertEqual("address_translation", satp.semantic_class)
        self.assertIn("riscv.mmu.root-change", satp.write_side_effect_ids)
        self.assertEqual({"ppn", "asid", "mode"}, {field.field_id for field in satp.fields})


if __name__ == "__main__":
    unittest.main()
