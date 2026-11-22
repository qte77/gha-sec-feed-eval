### Changed

- Workflow pin comments name the exact tag of the pinned SHA: the four `github/codeql-action`
  pins read `# v4.39.3` instead of `# v4`, and the `actions/upload-artifact` pin in `eval.yaml`
  reads `# v7.0.2` instead of `# v6.1.0` (the SHA was already v7.0.2). SHAs are unchanged;
  zizmor's `ref-version-mismatch` findings drop from 5 to 0.
