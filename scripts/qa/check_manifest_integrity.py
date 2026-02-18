#!/usr/bin/env python3
"""Validate canonical run manifest integrity and artifact consistency."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIRED_FILES = ("metadata.json", "summary.csv")


@dataclass
class Violation:
    manifest: Path
    message: str


def _resolve(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = (REPO_ROOT / candidate).resolve()
    return candidate


def _read_json_object(path: Path) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _read_summary_first_row(path: Path) -> Optional[Dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return next(reader, None)
    except Exception:
        return None


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return None


def _coerce_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _manifest_candidates(manifests_dir: Path) -> List[Path]:
    return sorted(manifests_dir.glob("run_*.json"))


def _resolve_results_path(raw_path: Any) -> Optional[Path]:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = (REPO_ROOT / candidate).resolve()
    return candidate


def _inside_results_root(target: Path, results_root: Path) -> bool:
    try:
        target.relative_to(results_root.resolve())
        return True
    except ValueError:
        return False


def _compare_equal(
    violations: List[Violation],
    manifest_path: Path,
    *,
    field: str,
    manifest_value: Any,
    metadata_value: Any,
) -> None:
    if manifest_value is None or metadata_value is None:
        return
    if str(manifest_value) != str(metadata_value):
        violations.append(
            Violation(
                manifest=manifest_path,
                message=(
                    f"{field} mismatch between manifest ({manifest_value}) "
                    f"and metadata.json ({metadata_value})"
                ),
            )
        )


def _compare_float(
    violations: List[Violation],
    manifest_path: Path,
    *,
    field: str,
    manifest_value: Any,
    summary_value: Any,
    tol: float = 1e-9,
) -> None:
    left = _coerce_float(manifest_value)
    right = _coerce_float(summary_value)
    if left is None or right is None:
        return
    if abs(left - right) > tol:
        violations.append(
            Violation(
                manifest=manifest_path,
                message=(
                    f"{field} mismatch between manifest ({left}) "
                    f"and summary.csv ({right})"
                ),
            )
        )


def _validate_single_manifest(
    manifest_path: Path,
    *,
    results_root: Path,
    required_files: Iterable[str],
) -> List[Violation]:
    violations: List[Violation] = []
    payload = _read_json_object(manifest_path)
    if payload is None:
        return [Violation(manifest=manifest_path, message="manifest is not a valid JSON object")]

    run_dir = _resolve_results_path(payload.get("results_path"))
    if run_dir is None:
        return [Violation(manifest=manifest_path, message="missing or invalid 'results_path'")]

    if not _inside_results_root(run_dir, results_root):
        return [
            Violation(
                manifest=manifest_path,
                message=f"results_path points outside results root: {run_dir}",
            )
        ]

    if not run_dir.exists() or not run_dir.is_dir():
        return [Violation(manifest=manifest_path, message=f"results_path does not exist: {run_dir}")]

    for required in required_files:
        if not (run_dir / required).exists():
            violations.append(
                Violation(
                    manifest=manifest_path,
                    message=f"missing required artifact: {required}",
                )
            )

    metadata_path = run_dir / "metadata.json"
    summary_path = run_dir / "summary.csv"
    metadata = _read_json_object(metadata_path) if metadata_path.exists() else None
    summary_row = _read_summary_first_row(summary_path) if summary_path.exists() else None

    if metadata_path.exists() and metadata is None:
        violations.append(Violation(manifest=manifest_path, message="metadata.json is not a valid JSON object"))
    if summary_path.exists() and summary_row is None:
        violations.append(Violation(manifest=manifest_path, message="summary.csv is missing header/data row"))

    if metadata:
        _compare_equal(
            violations,
            manifest_path,
            field="run_id",
            manifest_value=payload.get("run_id"),
            metadata_value=metadata.get("run_id"),
        )
        _compare_equal(
            violations,
            manifest_path,
            field="experiment_id",
            manifest_value=payload.get("experiment_id"),
            metadata_value=metadata.get("experiment_id"),
        )
        _compare_equal(
            violations,
            manifest_path,
            field="run_uid",
            manifest_value=payload.get("run_uid"),
            metadata_value=metadata.get("run_uid"),
        )
        _compare_equal(
            violations,
            manifest_path,
            field="attack_type",
            manifest_value=payload.get("attack_type"),
            metadata_value=metadata.get("attack_type"),
        )

        manifest_seed = _coerce_int(payload.get("seed"))
        metadata_seed = _coerce_int(metadata.get("seed"))
        if manifest_seed is not None and metadata_seed is not None and manifest_seed != metadata_seed:
            violations.append(
                Violation(
                    manifest=manifest_path,
                    message=(
                        f"seed mismatch between manifest ({manifest_seed}) "
                        f"and metadata.json ({metadata_seed})"
                    ),
                )
            )

    if summary_row:
        run_id = payload.get("run_id")
        if run_id is not None and summary_row.get("run_id") and str(run_id) != str(summary_row.get("run_id")):
            violations.append(
                Violation(
                    manifest=manifest_path,
                    message=(
                        f"run_id mismatch between manifest ({run_id}) "
                        f"and summary.csv ({summary_row.get('run_id')})"
                    ),
                )
            )

        attack_type = payload.get("attack_type")
        summary_attack = summary_row.get("attack")
        if attack_type and summary_attack and str(attack_type).lower() != str(summary_attack).lower():
            violations.append(
                Violation(
                    manifest=manifest_path,
                    message=(
                        f"attack_type mismatch between manifest ({attack_type}) "
                        f"and summary.csv ({summary_attack})"
                    ),
                )
            )

        _compare_float(
            violations,
            manifest_path,
            field="trust_threshold",
            manifest_value=payload.get("trust_threshold"),
            summary_value=summary_row.get("trust_threshold"),
        )

    manifest_run_id = payload.get("run_id")
    if manifest_run_id and run_dir.name != str(manifest_run_id):
        violations.append(
            Violation(
                manifest=manifest_path,
                message=(
                    f"run directory name ({run_dir.name}) does not match "
                    f"manifest run_id ({manifest_run_id})"
                ),
            )
        )

    return violations


def validate_manifests(
    *,
    manifests_dir: Path,
    results_root: Path,
    required_files: Iterable[str],
) -> tuple[List[Violation], int]:
    manifests = _manifest_candidates(manifests_dir)
    if not manifests:
        return [], 0

    violations: List[Violation] = []
    for manifest_path in manifests:
        violations.extend(
            _validate_single_manifest(
                manifest_path,
                results_root=results_root,
                required_files=required_files,
            )
        )
    return violations, len(manifests)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate run manifest integrity.")
    parser.add_argument(
        "--manifests-dir",
        default="results/_manifests",
        help="Directory containing run_*.json manifests (default: results/_manifests)",
    )
    parser.add_argument(
        "--results-root",
        default="results",
        help="Canonical results root directory (default: results)",
    )
    parser.add_argument(
        "--require-file",
        action="append",
        default=list(DEFAULT_REQUIRED_FILES),
        help=(
            "Artifact required in each results_path directory. "
            "Repeatable; defaults to metadata.json and summary.csv."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifests_dir = _resolve(args.manifests_dir)
    results_root = _resolve(args.results_root)
    required_files = list(dict.fromkeys(args.require_file))

    if not manifests_dir.exists():
        print(f"manifest integrity guard skipped: manifests dir not found: {manifests_dir}")
        return 0

    violations, checked = validate_manifests(
        manifests_dir=manifests_dir,
        results_root=results_root,
        required_files=required_files,
    )

    if checked == 0:
        print(f"manifest integrity guard skipped: no run manifests found in {manifests_dir}")
        return 0

    if violations:
        print("manifest integrity guard FAILED:")
        for item in violations:
            rel = item.manifest.relative_to(REPO_ROOT) if item.manifest.is_relative_to(REPO_ROOT) else item.manifest
            print(f"- {rel}: {item.message}")
        return 1

    print(
        "manifest integrity guard passed "
        f"({checked} manifests checked, required files: {', '.join(required_files)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
