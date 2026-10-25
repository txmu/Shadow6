# Shared safety contracts for v1.0

`python3 formal/check.py` checks 12 additional Lean 4.19.0 theorems, their
axiom dependencies and reviewed source hashes. Credit conservation, bounded
outstanding data, authenticated complete frames and capability intersection
are abstract models. Hashes detect source drift; they do not establish a
mechanical refinement from every Core or the Python socket facade to Lean.

Existing native proofs remain authoritative in their own scope:

- `Core-Ada/proof.gpr` covers the SPARK Cells and Domain_Policy units, including
  receive-state preservation and unauthenticated-cell rejection. Its runtime,
  JSON, socket and foreign-library boundaries remain outside that SPARK scope.
- `Core-Idris/src/Shadow6/Types.idr` and `Security/*.idr` carry existing native
  type contracts. The Idris security CI checks the modules and actual runtime
  regressions. FFI and operating-system behavior remain separate obligations.

The additional shared Lean model neither replaces nor reclassifies these Ada
and Idris proofs as unverified. Native compilation, platform tests and hardware
acceptance retain their own evidence. New source correspondence is recorded
only after review with `--refresh-sources`; CI never refreshes hashes.
