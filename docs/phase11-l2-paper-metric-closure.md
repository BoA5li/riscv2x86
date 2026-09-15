# Phase 11 L2 paper metric closure

Paper metric policy v2 and report v4 make every L2 numerator, denominator,
statistical unit, and bootstrap cluster explicit. Translation and eligibility
coverage use independent oracle fragments. Required-dimension dispositions use
fragments. Program differential results retain declared program/group units,
and concurrency results retain contract/campaign units. Every interval uses a
program/entry cluster bootstrap, so ten fragments from one program remain one
resampling cluster.

The fragment-level L2 metrics are:

- eligibility coverage: classified recognized fragments / all oracle fragments;
- attempted coverage: any required validator invoked / eligible fragments;
- complete execution coverage: every required dimension has verified-or-failed
  comparison evidence / eligible fragments;
- unconditional architectural verified: architectural verified / all oracle
  fragments, including unexecuted, inconclusive, needs-route, and unsupported;
- conditional architectural verified: architectural verified / fragments with
  L0 and L1 verified, L2 eligibility, and complete L2 execution;
- architectural verified among eligible: architectural verified / eligible;
- functional, diagnostic, inconclusive, and needs-route/unsupported rates remain
  separate and cannot enter an architectural numerator.

Each canonical L2 dimension additionally reports required, attempted,
architectural verified, functional-relation verified, diagnostic passed,
failed, inconclusive, not-run, and not-applicable counts. Unknown and legacy
dimension spellings are rejected by the corpus parser before report generation.

The JSON report embeds `metricDefinitions`, `dimensionMetricDefinition`, and
the complete statistical-unit map. The Markdown table renders those same
denominator definitions beside the numeric metrics.
