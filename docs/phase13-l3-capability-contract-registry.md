# L3-2: capability-driven contract/provider selection

The v2 runtime registry may declare an `L3` validator of type
`l3-capability-provider-registry`. Its config declares the execution profile,
source and target measurement capabilities, target environment ID and a sorted
provider catalog. Each provider declares its supported experiment classes,
property dimensions, execution profiles, required capabilities, supported
contract versions, and either explicit fragment/profile bindings or automatic
applicability. Each provider config contains the approved experiment contract
path/digest and source/target runner commands; the registered validator type
executes the selected provider. The original `l3-experiment-contract` factory
remains available.

Selection consumes the translated report's L3 intent and requirement sidecar.
It requires a complete, eligible, identity-consistent profile and the
provider's declared capabilities; it checks the actual contract digest,
approved relation, proof, program ID, required experimental properties and
contract version before selecting a runner. Exact fragment binding takes
precedence over exact profile binding, then general automatic providers.
Multiple matches at the same highest priority are `inconclusive`. An explicit
contract with stale bytes, wrong version or invalid binding blocks fallback
to an automatic candidate. An inapplicable explicit provider can be skipped.

The resolved plan records the contract content identity, selected provider
identity, source and target runner file digests, source and target build
artifact digests and target environment identity. These fields enter the
execution identity. For an executed, verified provider the L3 layer evidence
combines this execution identity with the provider's evidence identity. The
plan is saved before execution when an evaluation replay directory is
available; capability failure and ambiguity also produce an explicit plan.
The dispatcher checks runner files and contract bytes again before and after
execution. Changed inputs return `inconclusive`.

Only specifically approved properties are eligible for a verified result.
The current v2 contract supports access, control-flow, declared synchronization
and within-platform statistical trend properties. It has no approved generic
side-channel/speculation criterion; that requirement is `inconclusive` until
an appropriate later contract version is introduced. Registration and a
provider-declared class are not evidence of a real measurement.

Existing automatic batch inventories do not populate complete L3 intent,
capability catalogs or controlled source/target report producers; their L3
layer remains `not_run`. This stage provides a reusable selection interface
for later execution producers without changing the corpus aggregator.
