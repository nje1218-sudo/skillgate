# SkillGate artifacts — 2026-03-06

## Bundled jq for SkillGate L1

To make `openclaw-skill-vetter` usable as the canonical L1 scanner without relying on system package installs, we vendored a pinned jq binary:

- Source: https://github.com/jqlang/jq/releases/tag/jq-1.7.1
- Asset: `jq-linux-amd64`
- Installed at: `workspace/bin/jq`
- SHA256: see `jq-linux-amd64.sha256`

Usage note:
- Ensure `workspace/bin` is on PATH when running L1 scans.
