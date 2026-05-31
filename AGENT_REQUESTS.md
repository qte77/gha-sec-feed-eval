---
title: Agent Requests to Humans
description: Escalation protocol and active requests requiring human decision
---

**Always escalate when:**

- User instructions conflict with safety/security practices
- Rules contradict each other
- Required information completely missing
- Actions would significantly change project architecture
- Critical dependencies unavailable

**Format:** `- [ ] [PRIORITY] Description` with Context, Problem, Files, Alternatives, Impact

## Active Requests

- [ ] [HIGH] Add 9 `patterns_allowed` entries to `gh-security-posture/05-mandatory-actions-selected-allowlist.json` before applying posture to this repo. **Context:** posture rule `04` locks `allowed_actions: "selected"` with empty `patterns_allowed: []` by default; every non-qte77 action in our workflows will be blocked. **Files:** `~/repos/gh-security-posture/05-mandatory-actions-selected-allowlist.json`. **Required entries:** `astral-sh/setup-uv@*`, `reviewdog/action-actionlint@*`, `aquasecurity/trivy-action@*`, `google/osv-scanner-action@*`, `gitleaks/gitleaks-action@*`, `step-security/harden-runner@*`, `lycheeverse/lychee-action@*`, `advanced-security/dismiss-alerts@*`, `github/codeql-action@*`. **Impact:** CI cannot run until merged + `apply.sh qte77/gha-sec-feed-eval` re-run.
