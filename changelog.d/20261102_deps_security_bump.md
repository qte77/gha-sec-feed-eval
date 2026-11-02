### Security

- **Bumped four locked dependencies with known advisories**: anyio 4.13.0 -> 4.14.2,
  certifi 2026.5.20 -> 2026.10.18, pydantic-settings 2.14.1 -> 2.16.0, urllib3 2.7.0 -> 2.8.0.
  OSV listed 13 entries (GHSA and PYSEC, some duplicates) against the old pins; the new lock has
  none. `[tool.uv] exclude-newer`
  rolled from 2026-06-01 to 2026-10-19 so the fixed releases resolve; every other pin is unchanged.
