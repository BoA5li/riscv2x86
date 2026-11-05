#!/usr/bin/env python3
"""Plan, run and summarize complete captured-context inspection batches."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.project_activation_batches import main

if __name__=='__main__':raise SystemExit(main())
