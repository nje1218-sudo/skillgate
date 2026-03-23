# CLAUDE.md — AI Assistant Guide for SkillGate

This file provides guidance for AI assistants (Claude Code and similar tools) working on the SkillGate codebase. Keep it up to date as the project evolves.

---

## Project Overview

**SkillGate** is a project owned by Rong, licensed under the MIT License (2026).

> The repository is currently in its initial state — no application source code has been added yet. This document establishes conventions and workflows to follow as development begins.

---

## Repository Structure

```
SkillGate/
├── LICENSE          # MIT License
├── README.md        # Project title only — to be expanded
└── CLAUDE.md        # This file
```

Update this section as directories and files are added.

---

## Git Workflow

### Branches

| Branch | Purpose |
|--------|---------|
| `main` / `master` | Stable production-ready code. Never push directly. |
| `claude/<description>-<sessionId>` | AI-assisted feature branches |
| `feature/<description>` | Human-authored feature branches |

### Rules

- **Never push directly to `main` or `master`.**
- AI assistants must develop on a branch named `claude/<short-description>-<sessionId>`.
- Push with tracking: `git push -u origin <branch-name>`.
- Open a pull request for all changes; do not merge without review.

### Commit Messages

Use the imperative mood and keep the subject line under 72 characters:

```
Add user authentication endpoint
Fix null pointer in skill validation logic
Update CLAUDE.md with database conventions
```

Avoid vague messages like `fix stuff` or `WIP`.

---

## Development Setup

> **Note:** The tech stack has not been decided yet. When it is, document setup steps here.

Expected sections to add:

```
# Prerequisites
# Installation
# Running locally
# Environment variables
```

Never commit secrets or credentials. Use environment variables for all sensitive values and document their names (but not values) here.

---

## Code Conventions

> **Note:** Conventions will be defined once the language and framework are chosen. Add them here.

Guiding principles regardless of stack:

- Prefer clarity over cleverness.
- Keep functions small and focused on a single responsibility.
- Validate all external input (user data, API responses) at system boundaries.
- Do not add premature abstractions or over-engineer for hypothetical future requirements.

---

## Testing

> **Note:** Testing infrastructure has not been set up yet. Document the test runner and commands here once chosen.

Requirements:

- All new features must include tests.
- All tests must pass before merging to `main`/`master`.
- Do not skip or disable tests to make CI green.

---

## AI Assistant Guidelines

These instructions apply specifically to Claude Code and similar AI coding tools.

### General Behaviour

- **Read before editing.** Always read a file fully before making changes to it.
- **Minimal changes.** Only change what is directly requested. Do not refactor surrounding code, add docstrings, or clean up unrelated areas.
- **No over-engineering.** Do not design for hypothetical future use cases. Three similar lines of code is better than a premature abstraction.
- **No backwards-compatibility hacks.** If something is unused, delete it cleanly rather than leaving stubs or `_old` copies.
- **No security vulnerabilities.** Avoid SQL injection, XSS, command injection, and other OWASP top-10 issues. Validate at system boundaries only.

### Git Rules for AI Assistants

- Develop **only** on the designated `claude/` branch for the session.
- Commit frequently with clear messages describing what changed and why.
- Push with `git push -u origin <branch-name>`.
- **Never force-push** to shared branches.
- **Never push to `main` or `master`** without explicit user instruction.

### Risky Operations

Always confirm with the user before:

- Deleting files, branches, or database tables.
- Running destructive commands (`rm -rf`, `git reset --hard`, `git push --force`).
- Modifying CI/CD pipelines or deployment configuration.
- Sending messages or creating issues/PRs on behalf of the user.

### What NOT to Add Without Being Asked

- Comments or docstrings on code you did not change.
- Error handling for scenarios that cannot happen.
- Feature flags or backwards-compatibility shims.
- New dependencies, packages, or libraries.
- README sections, changelogs, or additional documentation files.

---

## Updating This File

When the project gains source code, dependencies, or infrastructure, update the relevant sections above. Specifically:

1. **Repository Structure** — add new top-level directories with a one-line description.
2. **Development Setup** — add prerequisite tools, install commands, and environment variables.
3. **Code Conventions** — add language/framework-specific style rules.
4. **Testing** — add the test runner command and any coverage requirements.
