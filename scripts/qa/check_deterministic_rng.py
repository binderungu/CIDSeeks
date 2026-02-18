#!/usr/bin/env python3
"""Guardrail: reject RNG constructors without explicit deterministic seeds."""

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
    REPO_ROOT / "src",
    REPO_ROOT / "scripts",
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


def _is_none_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _has_seed_arg(call: ast.Call) -> bool:
    if call.args:
        return not _is_none_literal(call.args[0])
    for kw in call.keywords:
        if kw.arg in {"seed", "x"}:
            return not _is_none_literal(kw.value)
    return False


def _collect_import_aliases(tree: ast.AST) -> tuple[Set[str], Set[str], Set[str], Set[str], Set[str]]:
    random_modules: Set[str] = set()
    random_ctor_aliases: Set[str] = set()
    numpy_modules: Set[str] = set()
    numpy_random_modules: Set[str] = set()
    numpy_default_rng_aliases: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "random":
                    random_modules.add(alias.asname or "random")
                elif alias.name == "numpy":
                    numpy_modules.add(alias.asname or "numpy")
                elif alias.name == "numpy.random":
                    numpy_random_modules.add(alias.asname or "random")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "random":
                for alias in node.names:
                    if alias.name == "Random":
                        random_ctor_aliases.add(alias.asname or alias.name)
            elif node.module == "numpy":
                for alias in node.names:
                    if alias.name == "random":
                        numpy_random_modules.add(alias.asname or alias.name)
            elif node.module == "numpy.random":
                for alias in node.names:
                    if alias.name == "default_rng":
                        numpy_default_rng_aliases.add(alias.asname or alias.name)

    # Support canonical names even without import alias discovery.
    random_modules.add("random")
    numpy_modules.add("numpy")
    numpy_random_modules.add("random")
    numpy_default_rng_aliases.add("default_rng")
    return random_modules, random_ctor_aliases, numpy_modules, numpy_random_modules, numpy_default_rng_aliases


def _is_random_ctor(
    call: ast.Call,
    *,
    random_modules: Set[str],
    random_ctor_aliases: Set[str],
) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id in random_ctor_aliases:
        return True
    if isinstance(func, ast.Attribute) and func.attr == "Random":
        if isinstance(func.value, ast.Name) and func.value.id in random_modules:
            return True
    return False


def _is_numpy_default_rng(
    call: ast.Call,
    *,
    numpy_modules: Set[str],
    numpy_random_modules: Set[str],
    numpy_default_rng_aliases: Set[str],
) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id in numpy_default_rng_aliases:
        return True
    if isinstance(func, ast.Attribute) and func.attr == "default_rng":
        if isinstance(func.value, ast.Name) and func.value.id in numpy_random_modules:
            return True
        if isinstance(func.value, ast.Attribute) and func.value.attr == "random":
            base = func.value.value
            if isinstance(base, ast.Name) and base.id in numpy_modules:
                return True
    return False


def _scan_file(path: Path) -> List[Violation]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return []

    (
        random_modules,
        random_ctor_aliases,
        numpy_modules,
        numpy_random_modules,
        numpy_default_rng_aliases,
    ) = _collect_import_aliases(tree)

    violations: List[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        source = _source_line(path, node.lineno)
        if _is_random_ctor(node, random_modules=random_modules, random_ctor_aliases=random_ctor_aliases):
            if not _has_seed_arg(node):
                violations.append(
                    Violation(
                        path=path,
                        line=node.lineno,
                        message="random.Random requires explicit non-None seed",
                        source=source,
                    )
                )
        elif _is_numpy_default_rng(
            node,
            numpy_modules=numpy_modules,
            numpy_random_modules=numpy_random_modules,
            numpy_default_rng_aliases=numpy_default_rng_aliases,
        ):
            if not _has_seed_arg(node):
                violations.append(
                    Violation(
                        path=path,
                        line=node.lineno,
                        message="numpy.random.default_rng requires explicit non-None seed",
                        source=source,
                    )
                )
    return violations


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect RNG constructors without explicit seeds")
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
        print("deterministic RNG guard FAILED:")
        for item in sorted(violations, key=lambda v: (str(v.path), v.line)):
            try:
                rel = item.path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                rel = str(item.path)
            print(f"- {rel}:{item.line}: {item.message}: {item.source}")
        return 1

    print("deterministic RNG guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
