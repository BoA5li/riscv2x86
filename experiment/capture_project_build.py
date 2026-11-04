#!/usr/bin/env python3
"""Capture configured native build tools; no shell-log execution or approval."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.project_build_capture import main
if __name__=='__main__':raise SystemExit(main())
