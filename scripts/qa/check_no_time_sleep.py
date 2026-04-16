#!/usr/bin/env python3
"""Guardrail: disallow blocking time.sleep in canonical SimPy/runtime paths."""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Set


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROTECTED_PATHS = [
    REPO_ROOT / "runner.py",
    REPO_ROOT / "simulate.py",
    REPO_ROOT / "src" / "simulation",
]


@dataclass
class Violation:
    path: Path
    line: int
    message: str
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


def _collect_time_aliases(tree: ast.AST) -> tuple[Set[str], Set[str]]:
    time_modules: Set[str] = {"time"}
    sleep_aliases: Set[str] = {"sleep"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "time":
                    time_modules.add(alias.asname or "time")
        elif isinstance(node, ast.ImportFrom) and node.module == "time":
            for alias in node.names:
                if alias.name == "sleep":
                    sleep_aliases.add(alias.asname or "sleep")
    return time_modules, sleep_aliases


def _is_time_sleep_call(node: ast.Call, *, time_modules: Set[str], sleep_aliases: Set[str]) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in sleep_aliases:
        return True
    if isinstance(func, ast.Attribute) and func.attr == "sleep":
        base = func.value
        if isinstance(base, ast.Name) and base.id in time_modules:
            return True
    return False


def _scan_file(path: Path) -> List[Violation]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [
            Violation(
                path=path,
                line=exc.lineno or 1,
                message="syntax error while parsing file",
                source="syntax-error",
            )
        ]

    time_modules, sleep_aliases = _collect_time_aliases(tree)
    violations: List[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_time_sleep_call(node, time_modules=time_modules, sleep_aliases=sleep_aliases):
            continue
        violations.append(
            Violation(
                path=path,
                line=node.lineno,
                message="blocking time.sleep is not allowed in canonical SimPy/runtime paths",
                source=_source_line(path, node.lineno),
            )
        )
    return violations


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect blocking time.sleep usage in SimPy/runtime paths")
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="File/dir path to scan (repeatable). Default: runner.py, simulate.py, src/simulation/.",
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
        print("time.sleep guard FAILED:")
        for item in sorted(violations, key=lambda v: (str(v.path), v.line)):
            try:
                rel = item.path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                rel = str(item.path)
            print(f"- {rel}:{item.line}: {item.message}: {item.source}")
        return 1

    print("time.sleep guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
