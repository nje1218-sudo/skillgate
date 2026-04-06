"""Shared utilities for SkillGate scanner scripts."""
from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
CODE_EXTS = {".py", ".js", ".ts", ".sh", ".bash", ".mjs", ".cjs", ".rb", ".go", ".rs"}


def iter_files(root: Path, max_size: int = 2_000_000):
    """Yield all non-skipped files under root up to max_size bytes."""
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.stat().st_size <= max_size:
            yield p
