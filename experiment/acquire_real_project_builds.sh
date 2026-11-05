#!/usr/bin/env bash
# Keep the Phase151 CLI; Python owns stage status and failure propagation.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/acquire_real_project_builds.py" "$@"
