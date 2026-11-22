### Security

- wcmatch 10.1 -> 11.2 (with bracex 2.6 -> 3.2) in uv.lock for GHSA-53pm-wgxf-c6qf (ReDoS,
  medium), which failed osv-scan. `[tool.uv] exclude-newer` moves from 2026-10-19 to
  2026-10-23 so that resolution can see wcmatch 11.2 (released 2026-10-22); the same cap made
  Dependabot's update runs of 2026-11-20 and 2026-11-21 fail with `dependency_file_not_resolvable`.
  uv 0.13.7 wrote the lock, which also moves `revision` 3 -> 5 and adds `default-groups` to the
  project entry; an older uv may rewrite both.
  osv-scan on main turns green only after the SBOM auto-PR that this `uv.lock` change triggers is
  merged, because it also scans the snapshots in `docs/SBOM/`.

### Fixed

- `eval-dispatch.yaml`: the `call_eval` job grants `contents: read`, which the called
  `eval.yaml` job needs; with `permissions: {}` at workflow level the caller granted none
  (CodeFactor `workflow-call-permissions`). The wrapper has no runs on record, so no failed run was
  observed.
