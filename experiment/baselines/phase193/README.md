# Phase193 shared-call fixture regression

The patch changes tests/docs only. Production translation/evaluation source and proof requirements are unchanged.

The fixture now requests a PLT call explicitly, preserves global/default symbol visibility, retains its object, and aligns/restores the stack around the call. Tests inspect actual PLT32/JUMP_SLOT metadata and the linked p-code transfer to the GOT slot. A deliberate PC32 relocation counterexample must still be rejected by the shared-library linker.

focused.log: 12 passed in 9.17 s.
regression.log: 101 passed in 323.18 s, including the focused tests. The counts overlap.

Local tools differ from the user's Ubuntu 18.04 environment; explicit relocation and counterexample checks remove reliance on the new assembler's plain-CALL default, but do not replace the user's old-toolchain rerun. No real GMP/full ABI/object/coverage/L2/L3 success is claimed.
