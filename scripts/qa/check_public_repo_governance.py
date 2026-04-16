#!/usr/bin/env python3
"""Guardrail: require baseline public governance/metadata files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIRED_PATHS = [
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CITATION.cff",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/workflows/ci-core.yml",
    ".github/workflows/ci-paper-core-gate.yml",
    ".github/workflows/codeql.yml",
    ".pre-commit-config.yaml",
]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Require baseline public governance files")
    parser.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="Repository root to validate (default: current repo root)",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        help="Additional relative path to require (repeatable)",
    )
    return parser.parse_args(argv)


def _missing_paths(repo_root: Path, required_paths: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for rel in required_paths:
        candidate = repo_root / rel
        if not candidate.exists():
            missing.append(rel)
    return missing


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    required_paths = list(DEFAULT_REQUIRED_PATHS)
    required_paths.extend(str(item) for item in args.require)
    missing = _missing_paths(repo_root, required_paths)

    if missing:
        print("public repo governance guard FAILED:")
        for rel in missing:
            print(f"- missing required file: {rel}")
        return 1

    print("public repo governance guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
