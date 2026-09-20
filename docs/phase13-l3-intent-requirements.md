# L3-1: explicit per-fragment experimental intent

The translated report may carry an `l3IntentProfile` for each finding. It must
be supplied by a frontend/compiler or translation-proof producer. The report
consumer checks the producer/proof identities, strict v1 field set, canonical
arrays, complete observation boundary and digest; it never classifies a
microarchitectural experiment from a mnemonic, L2 pattern, source file name,
function name or translated C text.

The profile has a `fragmentId`, `programId`, `intentKind`, experiment classes,
the source intent, an approved relation identity, required properties, source
and target capabilities, an observation boundary, excluded claims and producer
provenance. Each required property has a separate `unit`: `fragment`,
`program`, or `campaign`. A single program can therefore carry multiple
fragment-specific requirements while retaining a campaign-wide property.

After translation, `automatic_translation_command` writes
`translated_report.json.l3-requirements.json`, alongside the existing L2
sidecar. Without explicit complete intent, a finding is `inconclusive`, not
`verified` or `not_applicable`. A complete, authoritative `none` profile is
necessary for `not_applicable`. An approved intent without a target candidate
is reported `needs_route`, preserving its declared properties. An eligible
intent remains `not_run` until an L3 provider actually executes it.

The profile digest is included in each requirement digest; the manifest
digests its requirements. The v2 experiment contract adds
`intentProfileIdentity`, `requirementIdentity`, `approvedTargetRelationIdentity`
and `programId` on top of the original v1 fields. An explicitly configured
microarchitecture evaluation passes the translated report's requirement
sidecar to the validator. The v2 runner rejects missing or stale requirement,
program, proof or relation bindings as `inconclusive`, and includes the two
identities in final evidence. V1 contracts retain their original semantics;
they do **not** acquire a v2 requirement-binding claim by migration.

## Current production boundary

This stage builds the versioned intent/requirement transport and strict
identity checks. The current translator does not yet produce complete L3
intent profiles for general input programs; existing round1/round2 batch
plans still omit an experiment contract and continue to report `L3: not_run`.
Generating trustworthy profiles and selecting real experimental providers
requires later stages. The new requirement manifest does not schedule L3,
declare a microarchitecture-equivalent translation or contribute a verified
numerator on its own.
