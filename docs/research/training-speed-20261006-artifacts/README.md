# Public training-speed evidence

These files were selected explicitly from completed local measurements. JSON
and JUnit XML are sanitized, reserialized derivatives, not original-byte copies.
`manifest.json` maps every selected original SHA-256 to its published SHA-256.
Other recorded measurement and source hashes retain their original meaning;
only `launch-controls.json` report-index keys use published report hashes.
Launch controls are recorded-command declarations, not OS environment samples.

The four `*-budget-a.json` reports and `final-round-summary.json` form the final
matched-budget CPU/GPU comparison. `paper20-budget-gpu-rpc2.json` is one successful
20-client run: its singleton summary is not a before/after speed comparison.
The three failed 20-client reports and the interrupted report are retained as
failures, not performance baselines. Earlier and phase-2 measurements document
environment drift and all-cloud/threshold behavior at their recorded versions.

Reproduction sources are under `public/scripts/`, preserving original workspace
relative paths. Restore them at those original locations in a matching checkout
before using them; derived ROOT paths assume their original locations. Their
manifest hashes identify the copies supplied now, while report benchmark-script
hashes identify the versions actually measured and can differ. The local public
source snapshots and native build remain outside this bundle in
`<workspace>/tmp/speed-optimization-20261006/`; no binary or source archive is
included. Matching source/native/proof identities, cached MNIST, dependencies,
and the same thread budgets are required for a useful comparison.

`sitecustomize.py` is the optional Windows WMI fallback used only when
`DGFL_TEST_WMI_FALLBACK=1`; both sides must use the same setting. Publication did
not run these scripts, tests, benchmarks, training or service actions. The XML
contains 2,026 passed and 12 skipped testcases. Activation evidence contains
only public after-state verification; no before-state backup is included.

Sanitization replaces this workspace and the current user-profile absolute
prefixes, including dictionary keys and nested strings; it preserves timing,
proof parameters, public hashes, hardware metadata, run IDs and cleanup records.
It does not assert anonymization of those retained public fields.
