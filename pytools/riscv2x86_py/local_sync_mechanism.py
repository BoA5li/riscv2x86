"""Reviewed implementation allowlist for the bounded local SMC protocol.

Identity selects this review; it is not the proof. The argument and excluded
domains are recorded in docs/local-sync-mechanism-review.md. External process
and mapping assumptions remain explicit domain premises and are checked by the
observer where possible. A new QEMU/helper implementation needs a new review.
"""
from collections.abc import Mapping
from pathlib import Path
from .time_trace_harness import digest

SOURCE_DIGESTS = {
    "target/riscv/csr.c": "sha256:f4f9ed3876ec2b515426aa1ab6137b2b2c88d7bdde5362b74c5bee1ebc209659",
    "include/qemu/timer.h": "sha256:6fea4f0b8bb20789c369ce6c0ccd6fe41f064676769ee23370bb38e842c4bff6",
    "target/riscv/insn_trans/trans_rvi.c.inc": "sha256:569c8e8d77fe8b9654352126b854745fbdd343a50efdb69ca40a786c0f985542",
    "accel/tcg/translate-all.c": "sha256:6e4c2b92ec8dfb206c343e6b82a2885e0054c85a57b62c0533a9c855efc61a50",
    "accel/tcg/user-exec.c": "sha256:92f5c0c7797e0030f8e9b6c815ba6bf1b8ba9a2a663bea274fbd91eb4f020ed2",
    "accel/tcg/tb-maint.c": "sha256:d5495ee63146e7da87242b39c2c4b58fe514621703c5cb6dafe50ea9db9588ee"
}
TARGET_DIGESTS = {
    'runtime/riscv2x86_runtime_helpers.c': 'sha256:417112aaa35c3a57ce9c11e25ffaf76814444147d3fb8b2083ccfc3d04810b42',
    'runtime/include/riscv2x86_runtime_helpers.h': 'sha256:b506890aeff8f186d89f86064e56e40cd96042cb10e18418325e77c556e1c21c',
}


def require_reviewed_implementation(evidence):
    if not isinstance(evidence, Mapping) or evidence.get('sourceDigests') != SOURCE_DIGESTS:
        raise ValueError('ISS_SOURCE_MECHANISM_NOT_REVIEWED')
    root = Path(__file__).resolve().parents[2]
    if any(digest(root / path) != expected for path, expected in TARGET_DIGESTS.items()):
        raise ValueError('ISS_TARGET_MECHANISM_NOT_REVIEWED')
    return 'qemu-7.2-x86-cpuid-private-local-smc.v1'
