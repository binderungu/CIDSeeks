from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_flagship_freeze_dry_run_writes_reports(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    module = _load_module(
        repo_root / "scripts" / "maintenance" / "run_flagship_freeze.py",
        "run_flagship_freeze",
    )

    json_report = tmp_path / "freeze_report.json"
    md_report = tmp_path / "freeze_report.md"

    rc = module.main(
        [
            "--dry-run",
            "--allow-dirty",
            "--runner",
            "python",
            "--report-json",
            str(json_report),
            "--report-md",
            str(md_report),
            "--snapshot-dest",
            str(tmp_path / "public_snapshot"),
            "--bundle-path",
            str(tmp_path / "paper_core_bundle.tar.gz"),
            "--verify-report",
            str(tmp_path / "paper_core_bundle_verify.json"),
        ]
    )

    assert rc == 0
    assert json_report.exists()
    assert md_report.exists()

    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["status"] == "planned"
    assert payload["dry_run"] is True
    step_names = [step["name"] for step in payload["steps"]]
    assert step_names == [
        "simulate_flagship",
        "stats_gate",
        "build_bundle",
        "verify_bundle",
        "public_snapshot",
    ]

    simulate_cmd = payload["steps"][0]["command"]
    assert "--resume" in simulate_cmd
    assert "simulate.py" in simulate_cmd
    assert payload["git"]["commit"]

    markdown = md_report.read_text(encoding="utf-8")
    assert "FLAGSHIP_FREEZE_REPORT" in markdown
    assert "simulate_flagship" in markdown


def test_flagship_freeze_preflight_fails_on_dirty_repo(tmp_path: Path, monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    module = _load_module(
        repo_root / "scripts" / "maintenance" / "run_flagship_freeze.py",
        "run_flagship_freeze_dirty",
    )

    monkeypatch.setattr(
        module,
        "_git_info",
        lambda _repo_root: {
            "branch": "main",
            "commit": "deadbeef",
            "dirty": True,
            "dirty_count": 2,
            "dirty_entries_preview": [" M README.md", "?? notes.txt"],
        },
    )

    json_report = tmp_path / "preflight_failed.json"
    md_report = tmp_path / "preflight_failed.md"
    rc = module.main(
        [
            "--dry-run",
            "--report-json",
            str(json_report),
            "--report-md",
            str(md_report),
            "--snapshot-dest",
            str(tmp_path / "public_snapshot"),
            "--bundle-path",
            str(tmp_path / "paper_core_bundle.tar.gz"),
            "--verify-report",
            str(tmp_path / "paper_core_bundle_verify.json"),
        ]
    )

    assert rc == 1
    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["status"] == "preflight_failed"
    assert "dirty" in str(payload["preflight_error"]).lower()

    markdown = md_report.read_text(encoding="utf-8")
    assert "git_dirty" in markdown
    assert "preflight_error" in markdown
