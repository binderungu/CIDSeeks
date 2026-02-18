from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path


def _guard_script_path() -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / "qa" / "check_manifest_integrity.py"


def _write_manifest(path: Path, *, results_path: Path, run_id: str = "run_001") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "results_path": str(results_path),
        "run_id": run_id,
        "experiment_id": "exp_001",
        "run_uid": "uid_001",
        "seed": 42,
        "attack_type": "Collusion",
        "trust_threshold": 0.6,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_metadata(path: Path, *, run_id: str = "run_001") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "experiment_id": "exp_001",
        "run_uid": "uid_001",
        "seed": 42,
        "attack_type": "Collusion",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_summary(path: Path, *, run_id: str = "run_001") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["run_id", "attack", "trust_threshold"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "run_id": run_id,
                "attack": "Collusion",
                "trust_threshold": "0.6",
            }
        )


def _run_guard(*, manifests_dir: Path, results_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_guard_script_path()),
            "--manifests-dir",
            str(manifests_dir),
            "--results-root",
            str(results_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_manifest_integrity_guard_passes_for_valid_artifacts(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "smoke" / "run_001"
    manifests_dir = results_root / "_manifests"

    _write_metadata(run_dir / "metadata.json", run_id="run_001")
    _write_summary(run_dir / "summary.csv", run_id="run_001")
    _write_manifest(manifests_dir / "run_001.json", results_path=run_dir, run_id="run_001")

    completed = _run_guard(manifests_dir=manifests_dir, results_root=results_root)

    assert completed.returncode == 0
    assert "manifest integrity guard passed" in completed.stdout


def test_manifest_integrity_guard_fails_when_metadata_missing(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "smoke" / "run_001"
    manifests_dir = results_root / "_manifests"

    _write_summary(run_dir / "summary.csv", run_id="run_001")
    _write_manifest(manifests_dir / "run_001.json", results_path=run_dir, run_id="run_001")

    completed = _run_guard(manifests_dir=manifests_dir, results_root=results_root)

    assert completed.returncode == 1
    assert "missing required artifact: metadata.json" in completed.stdout


def test_manifest_integrity_guard_fails_on_run_id_mismatch(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "smoke" / "run_001"
    manifests_dir = results_root / "_manifests"

    _write_metadata(run_dir / "metadata.json", run_id="run_002")
    _write_summary(run_dir / "summary.csv", run_id="run_001")
    _write_manifest(manifests_dir / "run_001.json", results_path=run_dir, run_id="run_001")

    completed = _run_guard(manifests_dir=manifests_dir, results_root=results_root)

    assert completed.returncode == 1
    assert "run_id mismatch between manifest" in completed.stdout
