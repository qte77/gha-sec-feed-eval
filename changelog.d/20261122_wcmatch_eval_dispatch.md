### Security

- wcmatch 10.1 -> 11.2 (with bracex 2.6 -> 3.2) in uv.lock for GHSA-53pm-wgxf-c6qf (ReDoS,
  medium), which failed osv-scan. `[tool.uv] exclude-newer` moves from 2026-10-19 to
  2026-10-23 so that resolution can see wcmatch 11.2 (released 2026-10-22); the same cap kept
  Dependabot's wcmatch updates from resolving.

### Fixed

- `eval-dispatch.yaml`: the `call_eval` job grants `contents: read`, which the called
  `eval.yaml` job needs. With `permissions: {}` at workflow level, the manual dispatch wrapper
  could not start.
