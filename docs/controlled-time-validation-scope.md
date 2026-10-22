# Controlled TIME read-stream profile

This independently selected environment replaces only Linux-user RV64 TIME
reads in a separate pinned QEMU build. Native QEMU is retained. Source and
target consume the same external sequence of unsigned 64-bit values and record
each read. The observer checks event indices, read sites, results, counts,
ordering, actual artifacts and termination. Invalid/exhausted transport fails
execution and never becomes a counter value.

The currently registered model is an **isolated logical read stream**, not a
complete architectural TIME clock implementation. Arbitrary finite trajectories
exercise result flow and wraparound; they establish no tick frequency, elapsed
time, clock progress between reads, simultaneous-hart agreement or native TSC
relation. A future full-clock route needs a legal clock model and a proof of
how sampling events relate to that model, plus corresponding observations.

The process must be single threaded, without asynchronous readers. Trace files
are reserved, fresh and inaccessible to the program's modeled operations; file
resource observations and arbitrary enclosing-function instrumentation are
outside the profile. The current scope is the approved no-argument function
that reads and directly returns the 64-bit result. Compiler shell and access
facts are independently checked; they do not supply missing machine privilege,
VM, delegation or interrupt facts.

The environment owner explicitly selects this configuration. The approval is
conditional on this source model; passing this profile never licenses native
TIME translation. Each case and each L1/L2 result binds the backend, complete
runner command, observer and contract. Central reload compares those identities
against the outer case report. Aggregation separates environments. Native TIME,
full TIME clock semantics, physical timing and L3 remain unverified.
