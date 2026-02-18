#!/usr/bin/env python3
"""Export a public-safe repository snapshot without private git history."""

from __future__ import annotations

import argparse
import fnmatch
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Sequence


DEFAULT_DENY_PATTERNS = [
    "AGENTS.md",
    "docs/06_CODEX_RULES.md",
    "docs/07_THREAD_STARTERS.md",
    "references/*.md",
]
DEFAULT_ALLOW_PATTERNS = [
    "references/README.md",
]


def _run_git(repo_root: Path, args: Sequence[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
    return False


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export a clean, public-ready snapshot from current working tree."
    )
    parser.add_argument(
        "--dest",
        default="/tmp/vibe-cids-public",
        help="Destination directory for exported snapshot.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace destination directory if it already exists.",
    )
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="Include untracked non-ignored files from working tree.",
    )
    parser.add_argument(
        "--deny",
        action="append",
        default=[],
        help="Extra path pattern to exclude from snapshot (repeatable).",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        help="Path pattern to include even if excluded by deny list (repeatable).",
    )
    parser.add_argument(
        "--init-git",
        action="store_true",
        help="Initialize a fresh git repo in destination and create first commit.",
    )
    return parser.parse_args(list(argv))


def _copy_files(
    repo_root: Path,
    destination: Path,
    files: Sequence[str],
) -> None:
    for rel in files:
        src = repo_root / rel
        if not src.exists() or not src.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)


def _init_git_repo(destination: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=destination, check=True)
    subprocess.run(["git", "add", "."], cwd=destination, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Public snapshot: initial import"],
        cwd=destination,
        check=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    repo_root = Path(__file__).resolve().parents[2]
    destination = Path(args.dest).expanduser().resolve()

    if destination.exists():
        if not args.overwrite:
            raise FileExistsError(
                f"Destination already exists: {destination} (use --overwrite)"
            )
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=False)

    tracked_files = _run_git(repo_root, ["ls-files"]).splitlines()
    candidate_files: List[str] = [item.strip() for item in tracked_files if item.strip()]
    if args.include_untracked:
        untracked = _run_git(repo_root, ["ls-files", "--others", "--exclude-standard"]).splitlines()
        candidate_files.extend(item.strip() for item in untracked if item.strip())

    deny_patterns = list(DEFAULT_DENY_PATTERNS)
    deny_patterns.extend(args.deny)
    allow_patterns = list(DEFAULT_ALLOW_PATTERNS)
    allow_patterns.extend(args.allow)

    included: List[str] = []
    excluded_sensitive: List[str] = []
    seen = set()
    for rel in sorted(candidate_files):
        if rel in seen:
            continue
        seen.add(rel)
        if _matches_any(rel, deny_patterns) and not _matches_any(rel, allow_patterns):
            excluded_sensitive.append(rel)
            continue
        included.append(rel)

    _copy_files(repo_root, destination, included)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_repo": str(repo_root),
        "source_branch": _run_git(repo_root, ["branch", "--show-current"]).strip(),
        "source_commit": _run_git(repo_root, ["rev-parse", "HEAD"]).strip(),
        "destination": str(destination),
        "included_files": len(included),
        "excluded_sensitive_files": excluded_sensitive,
        "include_untracked": bool(args.include_untracked),
    }
    (destination / "PUBLIC_EXPORT_REPORT.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    if args.init_git:
        _init_git_repo(destination)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
