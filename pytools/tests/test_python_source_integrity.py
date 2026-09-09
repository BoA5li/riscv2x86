"""Repository-level integrity checks for Python source artifacts."""

from pathlib import Path


def test_python_sources_do_not_contain_nul_bytes() -> None:
    """Reject binary corruption before Python reaches module import time."""
    package_root = Path(__file__).resolve().parents[1] / "riscv2x86_py"
    corrupted = [
        str(path.relative_to(package_root))
        for path in sorted(package_root.rglob("*.py"))
        if b"\x00" in path.read_bytes()
    ]
    assert corrupted == [], f"Python sources contain NUL bytes: {corrupted}"
