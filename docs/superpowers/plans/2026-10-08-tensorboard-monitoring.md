# TensorBoard monitoring implementation plan

**Goal:** Deliver real accuracy/loss and local hardware charts in the existing monitoring page, with an embedded native TensorBoard backed by the same recorded evidence.

**Design:** See ../specs/2026-10-08-tensorboard-monitoring.md. Preserve cryptographic and training behavior. Reuse the isolated GitHub clone and its existing Vue/FastAPI stack.

1. Extend independent telemetry sampling with RAM, filesystem capacity, process RSS/CPU and detached live snapshots. Write and run targeted tests first.
2. Implement optional TensorBoard event export and a lazy same-origin ASGI adapter. Test actual event files, repeat/restart export and TensorBoard HTTP data endpoints.
3. Connect the runner lifecycle and API routes; expose cached live resources and isolate export failures. Test these integration contracts before implementation.
4. Add measured SVG curves and a lazy TensorBoard panel to Monitor.vue. Test data normalization, missing samples, request lifecycle and build the production frontend.
5. Update dependency locks, offline/deployment guidance and license notices. Run the affected Python tests, frontend tests/build and a browser smoke check. Independently review the complete diff and correct material findings.

Parallel ownership: telemetry, TensorBoard implementation, and frontend have separate agents. Root owns runner/control integration, dependency/docs changes, and final verification. No push, external publication or changes to the older original checkout are required.
