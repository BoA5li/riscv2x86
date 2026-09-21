# L3 batch enrollment and reporting

The translator writes `translated_report.json.l3-requirements.json` for every
translated source. Classification comes from a versioned proof-side intent.
An absent or incomplete intent remains `inconclusive`; an L3 provider registered
for a source never proves that its fragments have a complete intent.

## Enrolling a controlled experiment

For `corpus/sub/example.c`, place
`<l3-provider-directory>/sub/example.c.l3-providers.json` with this structure:

```json
{
  "schemaVersion": "riscv2x86.l3-batch-provider-binding.v1",
  "sourceRelativePath": "sub/example.c",
  "sourceDigest": "sha256:<64 hex digits>",
  "executionProfile": "rv64gc-user-to-x86_64-user",
  "environmentId": "auto-rv64gc-qemu-x86-native-v1",
  "sourceCapabilities": ["registered-source-capability"],
  "targetCapabilities": ["registered-target-capability"],
  "providers": ["<full riscv2x86.l3-validator-provider.v1 objects, sorted by providerId>"],
  "manifestIdentity": "sha256:<digest of canonical JSON without this field>"
}
```

The provider's contract must bind the exact intent profile, requirement,
proof, program, relation and translation plan. Its runner commands, binary
fingerprints, contract digest, environment and source/target build artifacts
are bound to the resolved execution identity. The registry resolves each
fragment separately; a single program can select distinct approved contracts.
Missing capabilities and ambiguous providers are reported without selecting
an arbitrary fallback. Supply a specific observation boundary and controlled
source/target reports; no raw counter equivalence is inferred.

```sh
PYTHONPATH=pytools python -m riscv2x86_py.automatic_batch_cli \
  --input "$CORPUS" --frontend "$FRONTEND" \
  --l3-provider-directory "$L3_BINDINGS" \
  --output-directory "$OUT" --jobs 1 --timeout-seconds 600
```

`--l3-diagnostic` explicitly selects target-only diagnostics for approved
functional fallback experiments; such results do not enter architectural
intent rates. Without a binding the L3 layer stays `not_run`; a complete
authoritative `none` intent can instead be `not_applicable`.

## Denominators and independent samples

`batch-evaluation.json.l3Coverage` reports fragment classification, eligible,
not applicable, needs route, attempted, complete comparison, architectural
intent and target diagnostic counts. An invocation is recorded separately
from complete source/target comparison. The batch denominator is its
**independently recognized** fragment inventory. Only the paper corpus oracle
can provide a denominator of **all expected** fragments, including missing
recognition; this is why batch counts must not be called unconditional oracle
rates.

The paper report's `metricDefinitions` states every L3 numerator and
denominator. Fragment rates use oracle fragments. Declared program/group
rates use validation units. Statistical uncertainty clusters by program or
entry, and campaign aggregation uses independent program/campaign identities.
Ten fragments in one program remain one bootstrap cluster. Experiment
conclusion preservation is limited to preregistered performance trends with
complete, valid comparisons on both platforms. Environment provenance and
observed experiment contract schema versions accompany the JSON report.

CI runs schema, gate, trace, experiment and aggregation tests on ordinary
GitHub runners. Scheduled/manual controlled experiments emit an explicit
`not_run` availability artifact when no dedicated runner is configured.
Configured campaigns require repository variables `L3_CONTROLLED_RUNNER_LABEL`,
`L3_CONTROLLED_CORPUS`, `L3_CONTROLLED_FRONTEND` and
`L3_CONTROLLED_PROVIDERS`; their real results are archived separately.
