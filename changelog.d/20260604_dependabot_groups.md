### Changed

- **Dependabot now groups updates per ecosystem into a single weekly PR**
  ([docs](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#groups)).
  `pip` updates roll up under a `python-deps` group; `github-actions`
  updates roll up under a `github-actions` group. Pattern `"*"` matches
  every package in scope. Reduces weekly PR churn from up to N per
  ecosystem to 2.
