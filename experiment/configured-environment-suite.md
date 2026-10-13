# Configured environment experiment

Privileged, instruction-stream synchronization, and CSR counter routes are
evaluated in a second experiment.  The default strict run never consumes
environment sidecars.  This prevents an environment-specific result from
being reported as unconditional translation coverage.

The manifest schema is `riscv2x86.configured-environment-suite.v1` and has the
following shape:

```json
{
  "schemaVersion": "riscv2x86.configured-environment-suite.v1",
  "sourceRoot": "../generated-suite",
  "cases": [
    {
      "sourceRelativePath": "case_016_<digest>.c",
      "sourceDigest": "sha256:<source-bytes-digest>",
      "fragmentId": "<frontend-fragment-id>",
      "route": "privileged",
      "sidecar": "config/case_016_<digest>.c.privileged-environment.json"
    }
  ],
  "manifestIdentity": "sha256:<canonical-manifest-digest>"
}
```

Use route `privileged` for ECALL/WFI (`case_016` and `case_022`),
`instruction_stream_sync` for `case_024`, and `csr` for `case_029`.  Sidecars
must retain their production file names:

- `<source>.privileged-environment.json`
- `<source>.instruction-stream-sync.json`
- `<source>.csr-environment.json`

The runner validates the manifest identity, source digest, fragment binding,
route schema, referenced runtime files, and route-specific completeness before
starting either experiment.  It then writes independent `strict/` and
`configured/` batch outputs plus `configured-environment-comparison.json`.

```sh
python3 -m riscv2x86_py.configured_environment_suite \
  --manifest experiment/configured-environment/suite.json \
  --frontend build/riscv2x86 \
  --output-root experiment/results/configured-$(date -u +%Y%m%dT%H%M%SZ)
```

Contract values are intentionally not generated from instruction text.  They
must be supplied by the trusted execution environment/runtime owner; a missing
or stale contract remains fail-closed.
