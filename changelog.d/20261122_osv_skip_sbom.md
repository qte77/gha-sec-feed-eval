### Changed

- `osv-scanner.yaml`: the scan skips `docs/SBOM/` (`--x-exclude=r:docs/SBOM$`, osv-scanner
  v2.7.1), so the generated snapshots in `docs/SBOM/` no longer fail osv-scan on main after a
  dependency fix, before the next SBOM auto-PR is merged. `uv.lock` is still scanned.
