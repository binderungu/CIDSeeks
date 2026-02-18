#!/usr/bin/env python3
"""Guardrail: prevent new legacy imports in canonical runtime paths."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[2]

# Canonical runtime areas that must not introduce new legacy dependencies.
PROTECTED_PATHS = [
    REPO_ROOT / "runner.py",
    REPO_ROOT / "simulate.py",
    REPO_ROOT / "src" / "main.py",
    REPO_ROOT / "src" / "ui",
    REPO_ROOT / "src" / "evaluation",
    REPO_ROOT / "src" / "simulation" / "core",
    REPO_ROOT / "src" / "simulation" / "methods",
    REPO_ROOT / "src" / "simulation" / "modules",
    REPO_ROOT / "scripts" / "qa",
]

# Legacy files still retained for compatibility/history (excluded from checks).
SKIP_FILES: set[str] = set()

# Banned legacy import prefixes (absolute and relative-import module values).
LEGACY_PREFIXES = [
    "simulation.legacy",
    "simulation.scenario",
    "simulation.simulator",
    "simulation.reporting",
    "simulation.visualization",
    "simulation.export",
    "simulation.monitoring",
    "simulation.runner",
    "src.simulation.legacy",
    "src.simulation.scenario",
    "src.simulation.simulator",
    "src.simulation.reporting",
    "src.simulation.visualization",
    "src.simulation.export",
    "src.simulation.monitoring",
    "src.simulation.runner",
    "legacy",
    "scenario",
    "simulator",
    "reporting",
    "visualization",
    "simulation.modules.authentication.auth_manager",
    "simulation.modules.authentication.core_auth_manager",
    "simulation.modules.privacy.privacy_manager",
    "simulation.modules.collaboration.collab_manager",
    "simulation.modules.attacks.sybil",
    "simulation.modules.attacks.collusion",
    "simulation.modules.attacks.betrayal",
    "simulation.modules.attacks.pmfa",
    "simulation.modules.attacks.core_attacks",
    "simulation.modules.attacks.attack_coordinator",
    "simulation.modules.database.database_manager",
    "simulation.modules.database.database_module",
    "simulation.modules.ids.ids_module",
    "simulation.core.simulation_iteration",
    "simulation.core.simulation_status",
    "simulation.utils.exceptions",
    "simulation.utils.logger",
    "simulation.utils.theme",
    "simulation.config.experiment_runner",
    "simulation.config.config_manager",
    "src.simulation.config.experiment_runner",
    "src.simulation.config.config_manager",
    "modules.authentication.auth_manager",
    "modules.authentication.core_auth_manager",
    "modules.privacy.privacy_manager",
    "modules.collaboration.collab_manager",
    "modules.attacks.sybil",
    "modules.attacks.collusion",
    "modules.attacks.betrayal",
    "modules.attacks.pmfa",
    "modules.attacks.core_attacks",
    "modules.attacks.attack_coordinator",
    "modules.database.database_manager",
    "modules.database.database_module",
    "modules.ids.ids_module",
    "core.simulation_iteration",
    "core.simulation_status",
    "utils.exceptions",
    "utils.logger",
    "utils.theme",
    "config.experiment_runner",
    "config.config_manager",
    "src.simulation.runner",
]

# Banned alias symbols that must not be imported from canonical packages.
BANNED_SYMBOL_IMPORTS: dict[str, set[str]] = {
    "simulation.modules": {"IDSModule", "TrustModule"},
    "simulation.modules.authentication": {"AuthenticationManager", "AuthManager"},
    "simulation.modules.ids": {"IDSModule"},
    "simulation.modules.collaboration": {"CollaborationManager"},
    "src.simulation.modules": {"IDSModule", "TrustModule"},
    "src.simulation.modules.authentication": {"AuthenticationManager", "AuthManager"},
    "src.simulation.modules.ids": {"IDSModule"},
    "src.simulation.modules.collaboration": {"CollaborationManager"},
    "modules": {"IDSModule", "TrustModule"},
    "modules.authentication": {"AuthenticationManager", "AuthManager"},
    "modules.ids": {"IDSModule"},
    "modules.collaboration": {"CollaborationManager"},
}


@dataclass
class Violation:
    path: Path
    line: int
    import_text: str


def _iter_python_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file():
            if path.suffix == ".py":
                yield path
            continue
        if path.is_dir():
            for py_file in path.rglob("*.py"):
                rel = py_file.relative_to(REPO_ROOT).as_posix()
                if rel in SKIP_FILES:
                    continue
                yield py_file


def _matches_legacy_prefix(module_name: str) -> bool:
    for prefix in LEGACY_PREFIXES:
        if module_name == prefix or module_name.startswith(prefix + "."):
            return True
    return False


def _source_line(path: Path, lineno: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _is_banned_symbol_import(module_name: str, imported_name: str) -> bool:
    banned_names = BANNED_SYMBOL_IMPORTS.get(module_name)
    if not banned_names:
        return False
    return imported_name in banned_names


def _scan_file(path: Path) -> List[Violation]:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if rel in SKIP_FILES:
        return []

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [Violation(path=path, line=exc.lineno or 1, import_text="syntax-error")]

    violations: List[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_name = alias.name
                if _matches_legacy_prefix(module_name):
                    violations.append(
                        Violation(
                            path=path,
                            line=node.lineno,
                            import_text=_source_line(path, node.lineno) or f"import {module_name}",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            if module_name and _matches_legacy_prefix(module_name):
                violations.append(
                    Violation(
                        path=path,
                        line=node.lineno,
                        import_text=_source_line(path, node.lineno) or f"from {module_name} import ...",
                    )
                )
            elif module_name:
                # Catch `from simulation.config import experiment_runner` style imports.
                for alias in node.names:
                    imported_name = alias.name
                    if imported_name == "*":
                        continue
                    joined_name = f"{module_name}.{imported_name}"
                    if _matches_legacy_prefix(joined_name):
                        violations.append(
                            Violation(
                                path=path,
                                line=node.lineno,
                                import_text=_source_line(path, node.lineno)
                                or f"from {module_name} import {imported_name}",
                            )
                        )
                    elif _is_banned_symbol_import(module_name, imported_name):
                        violations.append(
                            Violation(
                                path=path,
                                line=node.lineno,
                                import_text=_source_line(path, node.lineno)
                                or f"from {module_name} import {imported_name}",
                            )
                        )
            elif not module_name:
                # Catch `from . import simulator` style imports in package-relative form.
                for alias in node.names:
                    if _matches_legacy_prefix(alias.name):
                        violations.append(
                            Violation(
                                path=path,
                                line=node.lineno,
                                import_text=_source_line(path, node.lineno)
                                or f"from . import {alias.name}",
                            )
                        )

    return violations


def main() -> int:
    violations: List[Violation] = []
    for file_path in _iter_python_files(PROTECTED_PATHS):
        violations.extend(_scan_file(file_path))

    if violations:
        print("legacy import guard FAILED:")
        for item in sorted(violations, key=lambda v: (str(v.path), v.line)):
            rel = item.path.relative_to(REPO_ROOT).as_posix()
            print(f"- {rel}:{item.line}: {item.import_text}")
        return 1

    print("legacy import guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
