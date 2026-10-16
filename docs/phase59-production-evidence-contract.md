# Production-chain evidence and compiler provenance

Baseline: phase58-effect-presence-classification, remote commit
069c4aa582ba3fe1a99beb6a0c0f1d011218af63.

The fence regression searched batch summaries for attempt evidence even though
the summary deliberately excludes attempts. The new l2_evidence_reader follows
case.resultPath, confines it to the batch/case, recomputes evaluationIdentity,
checks the summary, and parses L2 layer details with L2FragmentResult.from_dict.
When requirements are supplied, their manifest, fragment set, identities and
required dimensions are validated. Independent attempts are retained separately.
This reader validates result content and references; it does not replace the
provider validators that recompute execution and observation payload identities.

The scalar regression exposed inconsistent candidate matching: injection used
exact byte ranges whereas fragment materialization also used structured compiler
source coordinates. Both now use resolve_compiler_fragment_candidate. The
compiler binding survives report serialization. Missing, rejected and matched
joins are explicit. Ambiguity and structurally complete operand disagreement
remain errors. A scalar automatic sidecar cannot bypass a rejected production
join; legacy/manual inputs without a production join retain their existing path.

Automatic runs preserve frontend-report.json and compiler-candidates.json before
enriching raw_report.json. The latter is backend input, not independent original
compiler evidence. The snapshot hashes its complete payload and references the
original frontend report. Freshness checks prevent reuse of these output files.
compiler-fragment-joins.json records per-fragment dispositions.

compilerAuthorityConsumption is produced only after the closed candidate's
identity and its actual canonical operand consumer agree on index, declaration,
value node, access, width and signedness. It references the canonical authority
identity; the existing sidecar schema and hash contract remain unchanged. It is
an auditable consumption envelope, not a new semantic proof or runtime sample.
The real production regression independently validates the snapshot and compares
original compiler carriers/value nodes against the closed payload. Fence is not
required to fabricate scalar provenance.

Validation: related Python regressions pass; real cross-ISA tests skip here
because the necessary frontend/Clang/RISC-V gcc/QEMU toolchain is unavailable.
No generated-suite success is claimed from these local tests. Run the real
production-chain tests on the experiment host before a new generated-suite run.
Newly required artifacts are not retrofitted into old experiment directories.

These changes address evidence access and provenance. They do not extend atomic,
asm-goto, configured runtime, or L3 semantic capability.
