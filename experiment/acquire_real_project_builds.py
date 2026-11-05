#!/usr/bin/env python3
"""Original-project acquisition with persistent stage status, not acceptance."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pytools'))
from riscv2x86_py.project_acquisition import main
if __name__ == '__main__':
    raise SystemExit(main())
