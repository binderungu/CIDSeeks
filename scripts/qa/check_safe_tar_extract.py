#!/usr/bin/env python3
"""Guardrail: enforce safe tar extraction patterns."""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROTECTED_PATHS = [
    REPO_ROOT / "runner.py",
    REPO_ROOT / "simulate.py",
    REPO_ROOT / "src",
    REPO_ROOT / "scripts",
]


@dataclass
class Violation:
    path: Path
    line: int
    source: str


def _iter_python_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file():
            if path.suffix == ".py":
                yield path
            continue
        if path.is_dir():
            for py_file in path.rglob("*.py"):
                yield py_file


def _resolve_targets(raw_paths: Sequence[str]) -> List[Path]:
    if not raw_paths:
        return DEFAULT_PROTECTED_PATHS
    targets: List[Path] = []
    for raw in raw_paths:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = (REPO_ROOT / candidate).resolve()
        targets.append(candidate)
    return targets


def _source_line(path: Path, lineno: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _is_unsafe_extractall_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "extractall":
        return False

    kw_names = {kw.arg for kw in node.keywords if kw.arg}
    # Require at least one explicit safety control:
    # - members: caller supplies pre-screened members
    # - filter: Python 3.12 extraction filter
    if "members" in kw_names or "filter" in kw_names:
        return False
    return True


def _scan_file(path: Path) -> List[Violation]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return []

    violations: List[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_unsafe_extractall_call(node):
            violations.append(
                Violation(
                    path=path,
                    line=node.lineno,
                    source=_source_line(path, node.lineno),
                )
            )
    return violations


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect unsafe tar.extractall usage")
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="File/dir path to scan (repeatable). Default: canonical runtime paths.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    cli_args = list(argv) if argv is not None else sys.argv[1:]
    args = parse_args(cli_args)
    targets = _resolve_targets(args.path)
    violations: List[Violation] = []
    for file_path in _iter_python_files(targets):
        violations.extend(_scan_file(file_path))

    if violations:
        print("tar extraction safety guard FAILED:")
        for item in sorted(violations, key=lambda v: (str(v.path), v.line)):
            try:
                rel = item.path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                rel = str(item.path)
            print(f"- {rel}:{item.line}: unsafe tar.extractall call: {item.source}")
        return 1

    print("tar extraction safety guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
