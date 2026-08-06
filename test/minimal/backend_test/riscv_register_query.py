# -*- coding: ascii -*-
# tests/ghidra_scripts/riscv_register_query.py
# This script is executed by Ghidra support/pythonRun
# Not a CPython pytest test file
# Use Python2/Jython compatible syntax, avoid Python3 exclusive features

import json

from ghidra.program.model.lang import LanguageID
from ghidra.program.util import DefaultLanguageService

LANGUAGE_ID = "RISCV:LE:64:default"

def main():
    language_service = DefaultLanguageService.getLanguageService()
    language = language_service.getLanguage(LanguageID(LANGUAGE_ID))

    if language is None:
        raise RuntimeError("cannot load Ghidra language: " + LANGUAGE_ID)

    address_factory = language.getAddressFactory()
    register_space = address_factory.getRegisterSpace()

    if register_space is None:
        raise RuntimeError("language has no register address space: " + LANGUAGE_ID)

    registers = []
    for reg in language.getRegisters():
        address = reg.getAddress()
        if address.getAddressSpace() != register_space:
            continue
        registers.append({
            "name": str(reg.getName()),
            "offset": int(address.getOffset()),
            "size": int(reg.getMinimumByteSize()),
            "bitLength": int(reg.getBitLength()),
            "isProcessorContext": bool(reg.isProcessorContext()),
        })

    result = {
        "ok": True,
        "language_id": LANGUAGE_ID,
        "registers": registers,
    }
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
