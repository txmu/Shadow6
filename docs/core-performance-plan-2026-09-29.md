# ~~Core performance implementation plan (2026-09-29)~~

**Archived 2026-10-04.** The implementation work from this plan was superseded
by the bounded Core changes and CI work recorded in
[linux-iperf-history-2026-09-26-to-28.md](linux-iperf-history-2026-09-26-to-28.md)
and the dated `performance-actions-*` records. This file is no longer an
active implementation checklist.

The original plan investigated scheduling, bounded batching, queue pressure,
and transport-specific throughput across the independent Core families. Its
proposals were design hypotheses, not measured outcomes. **The historical
1 Gbit/s receiver-throughput and 0.1% UDP-loss goals were not thereby met.**
Use the latest CI performance artifact and the dated iperf history for the
measured per-Core result; do not infer a performance result from plan completion.

Current cross-component work is tracked in the
[Native Profile and Named Service completion ledger](native-profile-runtime-plan.md).
