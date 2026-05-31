# Contributing to gha-sec-feed-eval

Shared technical workflow for human contributors and AI agents.
[README.md](README.md) covers project overview;
[AGENTS.md](AGENTS.md) carries AI-agent-only behavioural rules;
this document is the single source of truth for **how** to make
changes that pass CI and land cleanly on `main`.

## Quickstart

```bash
make setup_dev    # uv sync (default groups: dev + test)
make help         # canonical command list — every recipe with one-liner
make validate     # CI gate (lint + types + complexity + lint_md + lint_links + test_cov)
```

Every command in this document is discoverable via `make help`. If this
file disagrees with `make help`, `make help` wins.

## Test conventions

- **Mock external I/O.** The C1 feed fetch and EPSS live fetch are
  exercised only via fixtures (`tests/fixtures/feed-min.jsonl`,
  `tests/fixtures/feed-edge.jsonl`). HTTP boundary code never runs in
  unit tests.
- **Offline mode (`GSFE_OFFLINE=1`)** is the test default —
  `http_client.get()` raises if called. Tests asserting offline behaviour
  rely on this.
- **Network tests are opt-in.** Tag live external calls with
  `@pytest.mark.network`; they are excluded from `make test` by default
  and opt-in via `pytest -m network`.

## Commit + PR conventions

- **[Conventional Commits](https://www.conventionalcommits.org/)** for
  every commit message and PR title:
  `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `style`, `ci`, `perf`.
- **Topic-grouped commits.** One logical concern per commit; tests and
  implementation co-committed unless using strict TDD
  (red → green → optional refactor, one commit per phase).
- **Touch only task-related code.** Bug fixes don't carry surrounding
  cleanup; refactors are their own PR.
- **PRs are squash-merged** (signed via GitHub web-flow). Each PR's
  topic commits collapse into a single tidy commit on `main`.

## Branch protection + GHA workflows

- **Direct pushes to `main` are blocked** by branch protection. All
  changes land via PR + squash-merge.
- **Tags on `v*` require signatures** (gh-security-posture rule `03`).
  The `tag-release.yaml` workflow creates signed tag objects via the
  GitHub API rather than `git tag -a -m`.
- **Pin every `uses:` to a full-length commit SHA** in any new or
  edited workflow (e.g. `actions/checkout@de0fac2e…`). Allowlisted
  actions are documented in `gh-security-posture/05-mandatory-actions-selected-allowlist.json`.

## Changelog fragments

`CHANGELOG.md` is owned by [scriv](https://github.com/nedbat/scriv).
Each PR adds **one fragment** under `changelog.d/`; no PR ever
hand-edits `CHANGELOG.md`. This eliminates the parallel-PR conflict
that hits every cross-cutting change.

```bash
make changelog_new        # creates + stages changelog.d/<topic>.md
                          # edit it: ### Added | ### Fixed | ### Security + one bullet
make changelog_preview    # preview the assembled next-release entry (scriv print)
```

A fragment file looks like:

```markdown
### Added

- One-sentence description of the change (#PR-number). Optional second
  sentence with motivation or non-obvious context.
```

## Release flow (3-workflow split)

1. **Bump + collect fragments + open PR.**
   `gh workflow run bump-my-version.yaml -f bump_type=minor` →
   `bump-my-version --no-tag` updates `pyproject.toml` + README badge,
   `scriv collect` rolls `changelog.d/` into `CHANGELOG.md`, workflow
   opens a release PR.
2. **Squash-merge the release PR.**
   `tag-release.yaml` triggers on push-to-`main` paths:`pyproject.toml`,
   diffs the version line, creates the **signed** annotated `v{new}`
   tag against the main commit via `POST /repos/.../git/tags` (signed
   tag required by gh-security-posture rule `03`).
3. **Publish release.**
   `gh workflow run publish-release.yaml` → extracts notes from the
   `## [vX.Y.Z]` block in `CHANGELOG.md`, creates the GitHub Release,
   runs Syft SBOM + `attest-build-provenance` on the source tarball.

`bump-my-version` no longer touches `CHANGELOG.md` (scriv owns it).

## Documentation pointers

- **[`docs/architecture.md`](docs/architecture.md)** — module map, data
  flow, boundary failure policy
- **[`docs/contracts.md`](docs/contracts.md)** — C1 input + C2 output specs
- **[`docs/scoring.md`](docs/scoring.md)** — priority formula + cve-sentry
  citation
- **[`docs/categories.md`](docs/categories.md)** — default ecosystems +
  consumer override guide
- **[`docs/consumer-guide.md`](docs/consumer-guide.md)** — reusable
  workflow integration (lands 2d)
- **[`docs/refresh-vendored-data.md`](docs/refresh-vendored-data.md)** —
  ATT&CK + D3FEND refresh runbook (lands 2b)
- **[`AGENTS.md`](AGENTS.md)** — AI agent behavioural rules
- **[`README.md`](README.md)** — project overview, quickstart
