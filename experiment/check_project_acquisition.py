#!/usr/bin/env python3
"""Check archive decoder availability. No source or semantic approval."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pytools'))
from riscv2x86_py.project_archive_stream import decoder
from riscv2x86_py.project_compile_context import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', action='append', required=True)
    args = parser.parse_args()
    rows = []
    for name in args.archive:
        try:
            path = Path(name).resolve(strict=True)
            rows.append({'archive': str(path), 'archiveDigest': digest(path),
                         'decoder': decoder(path), 'available': True})
        except (OSError, ValueError) as exc:
            rows.append({'archive': name, 'available': False, 'error': str(exc)})
    print(json.dumps({'schemaVersion': 'riscv2x86.project-acquisition-capabilities.v1',
                      'python': sys.executable, 'archives': rows,
                      'semanticApproval': False, 'sourceTreeMatchesRelease': False,
                      'productionAcceptanceComplete': False}, indent=2))
    return 0 if all(row['available'] for row in rows) else 2


if __name__ == '__main__':
    raise SystemExit(main())
