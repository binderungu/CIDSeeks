#!/usr/bin/env python3
"""Guardrail: block internal/sensitive files from staying git-tracked."""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List


DEFAULT_DENY_PATTERNS = [
    "AGENTS.md",
    "docs/06_CODEX_RULES.md",
    "docs/07_THREAD_STARTERS.md",
    "references/*.md",
]
DEFAULT_ALLOW_PATTERNS = [
    "references/README.md",
]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reject tracked internal/sensitive files")
    parser.add_argument(
        "--deny",
        action="append",
        default=[],
        help="Tracked path pattern to forbid (repeatable).",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        help="Tracked path pattern allowed even if matching deny list (repeatable).",
    )
    return parser.parse_args(argv)


def _tracked_files(repo_root: Path) -> List[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
    return False


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve().parents[2]
    deny_patterns = list(DEFAULT_DENY_PATTERNS)
    deny_patterns.extend(args.deny)
    allow_patterns = list(DEFAULT_ALLOW_PATTERNS)
    allow_patterns.extend(args.allow)

    violations: List[str] = []
    for tracked in _tracked_files(repo_root):
        if not _matches_any(tracked, deny_patterns):
            continue
        if _matches_any(tracked, allow_patterns):
            continue
        violations.append(tracked)

    if violations:
        print("public repo hygiene guard FAILED:")
        for item in violations:
            print(f"- tracked sensitive/internal file: {item}")
        return 1

    print("public repo hygiene guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
