---
name: New Language Adapter Request
about: Request surface-map and isolated PoC adapter support for a new programming language
title: '[ADAPTER] '
labels: enhancement
assignees: ''
---

**Requested Language / Runtime:**
[e.g. Ruby, PHP, Elixir, Swift, Scala]

**In-Process PoC & Network Isolation Strategy:**
- How can HTTP routes/controllers be invoked in-memory without opening external sockets?
- Concurrency barrier primitive for `RACE_DOUBLE_SPEND`:

**Isolation & Sandbox Requirements:**
- Cache directories to redirect into `.bughunt/.cache/`:
- Does the runtime require a full sandbox copy (`S/sandbox-fix/`) or can it import via `VERISEC_TARGET_ROOT`?

**Example Dual Commands:**
- Bash:
- PowerShell:
