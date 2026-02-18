from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from ui.experiment_summary_tab import ExperimentSummaryTab
from ui.services.experiment_store import AggregateArtifacts, RunArtifacts, RunIndex


def _write_manifest(manifest_path: Path, results_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps({"results_path": str(results_path)}),
        encoding="utf-8",
    )


def _write_metadata(run_dir: Path, *, run_id: str = "run_test", attack_type: str = "Collusion") -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(
        json.dumps({"run_id": run_id, "attack_type": attack_type}),
        encoding="utf-8",
    )


def test_run_index_uses_canonical_manifest_root_only(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "smoke" / "run_a"
    _write_metadata(run_dir, run_id="run_a")

    canonical_manifest = results_root / "_manifests" / "run_canonical.json"
    _write_manifest(canonical_manifest, run_dir.resolve())

    legacy_manifest = tmp_path / "runs" / "run_legacy.json"
    _write_manifest(legacy_manifest, run_dir.resolve())

    index = RunIndex(str(results_root), str(tmp_path / "runs"))
    selected = index.get_last_run_from_manifest()
    selected_run_path = index.get_last_run_results_path()

    assert selected is not None
    assert selected.resolve() == canonical_manifest.resolve()
    assert selected_run_path is not None
    assert selected_run_path.resolve() == run_dir.resolve()


def test_run_index_returns_none_without_canonical_manifest(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "paper_core" / "run_b"
    run_dir.mkdir(parents=True, exist_ok=True)

    legacy_manifest = tmp_path / "runs" / "run_legacy.json"
    _write_manifest(legacy_manifest, run_dir.resolve())

    index = RunIndex(str(results_root), str(tmp_path / "runs"))

    assert index.get_last_run_from_manifest() is None
    assert index.get_last_run_results_path() is None


def test_run_index_returns_none_when_manifest_points_outside_results_root(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    results_root.mkdir(parents=True, exist_ok=True)
    foreign_run = tmp_path / "foreign" / "run_x"
    foreign_run.mkdir(parents=True, exist_ok=True)

    canonical_manifest = results_root / "_manifests" / "run_foreign.json"
    _write_manifest(canonical_manifest, foreign_run.resolve())

    index = RunIndex(str(results_root), str(results_root / "_manifests"))

    assert index.get_last_run_from_manifest() is None
    assert index.get_last_run_results_path() is None


def test_run_index_returns_none_when_manifest_target_missing_metadata(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "smoke" / "run_missing_metadata"
    run_dir.mkdir(parents=True, exist_ok=True)

    canonical_manifest = results_root / "_manifests" / "run_missing_metadata.json"
    _write_manifest(canonical_manifest, run_dir.resolve())

    index = RunIndex(str(results_root), str(results_root / "_manifests"))

    assert index.get_last_run_from_manifest() is None
    assert index.get_last_run_results_path() is None


def test_run_index_ignores_legacy_meta_json_when_scanning_runs(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_dir = results_root / "smoke" / "run_meta_only"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(
        json.dumps({"run_id": "legacy_run", "attack": "LegacyAttack"}),
        encoding="utf-8",
    )

    index = RunIndex(str(results_root), str(results_root / "_manifests"))
    runs = index.scan_runs()

    assert runs == []


def test_run_artifacts_load_uses_metadata_json_not_legacy_meta(tmp_path: Path) -> None:
    run_dir = tmp_path / "results" / "smoke" / "run_artifacts"
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "metadata.json").write_text(
        json.dumps({"attack_type": "Collusion", "run_id": "run_artifacts"}),
        encoding="utf-8",
    )
    (run_dir / "meta.json").write_text(
        json.dumps({"attack": "LegacyAttack"}),
        encoding="utf-8",
    )
    pd.DataFrame({"round": [1], "mean_honest": [0.8], "mean_malicious": [0.2]}).to_csv(
        run_dir / "trust_gap_per_round.csv",
        index=False,
    )

    artifacts = RunArtifacts.load(run_dir)

    assert artifacts.meta.get("attack") == "Collusion"


def test_scan_runs_includes_only_manifest_backed_runs(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    run_manifested = results_root / "smoke" / "run_manifested"
    run_unmanifested = results_root / "smoke" / "run_unmanifested"

    _write_metadata(run_manifested, run_id="run_manifested", attack_type="Sybil")
    _write_metadata(run_unmanifested, run_id="run_unmanifested", attack_type="Betrayal")

    pd.DataFrame([{"run_id": "run_manifested", "attack": "Sybil"}]).to_csv(
        run_manifested / "summary.csv",
        index=False,
    )
    pd.DataFrame([{"run_id": "run_unmanifested", "attack": "Betrayal"}]).to_csv(
        run_unmanifested / "summary.csv",
        index=False,
    )

    canonical_manifest = results_root / "_manifests" / "run_manifested.json"
    _write_manifest(canonical_manifest, run_manifested.resolve())

    index = RunIndex(str(results_root), str(results_root / "_manifests"))
    runs = index.scan_runs()

    assert len(runs) == 1
    assert runs[0]["run_id"] == "run_manifested"


def test_aggregate_artifacts_load_reads_canonical_suite_outputs(tmp_path: Path) -> None:
    suite_dir = tmp_path / "results" / "smoke"
    suite_dir.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(
        [
            {
                "scenario": "smoke_test",
                "variant": "v00",
                "metric": "AUROC_final",
                "method": "CIDSeeks",
                "mean": 0.91,
                "n_seeds": 1,
            }
        ]
    ).to_csv(suite_dir / "aggregate_summary.csv", index=False)
    pd.DataFrame(
        [
            {
                "scenario": "smoke_test",
                "variant": "v00",
                "run_id": "run_1",
                "algo": "CIDSeeks",
                "attack": "Collusion",
                "AUROC_final": 0.91,
            }
        ]
    ).to_csv(suite_dir / "experiments.csv", index=False)
    pd.DataFrame([{"metric": "AUROC_final", "wilcoxon_p": 0.1}]).to_csv(
        suite_dir / "stats.csv",
        index=False,
    )

    artifacts = AggregateArtifacts.load(suite_dir)

    assert not artifacts.aggregate_summary.empty
    assert not artifacts.experiments.empty
    assert not artifacts.stats.empty


def test_experiment_summary_tab_builds_aggregate_context_from_canonical_tables(tmp_path: Path) -> None:
    class _Var:
        def __init__(self, value: str) -> None:
            self._value = value

        def get(self) -> str:
            return self._value

    suite_dir = tmp_path / "results" / "smoke"
    art = AggregateArtifacts(suite_dir)
    art.experiments = pd.DataFrame(
        [
            {
                "scenario": "smoke_test",
                "variant": "v00",
                "run_id": "run_a",
                "algo": "CIDSeeks",
                "attack": "Collusion",
                "AUROC_final": 0.9,
                "AUPRC_final": 0.88,
                "TTD_median": 4.0,
            },
            {
                "scenario": "smoke_test",
                "variant": "v00",
                "run_id": "run_b",
                "algo": "CIDSeeks",
                "attack": "Collusion",
                "AUROC_final": 1.0,
                "AUPRC_final": 0.92,
                "TTD_median": 6.0,
            },
        ]
    )
    art.aggregate_summary = pd.DataFrame(
        [
            {
                "scenario": "smoke_test",
                "variant": "v00",
                "metric": "FPR_h",
                "method": "CIDSeeks",
                "mean": 0.12,
                "n_seeds": 2,
            }
        ]
    )

    tab = ExperimentSummaryTab.__new__(ExperimentSummaryTab)
    tab.scenario_var = _Var("smoke_test")
    tab.method_var = _Var("CIDSeeks")
    tab.attack_var = _Var("Collusion")
    tab.run_var = _Var("run_a")

    summary = ExperimentSummaryTab._build_summary_context(tab, art)

    assert summary["scenario"] == "smoke_test"
    assert summary["method"] == "CIDSeeks"
    assert summary["attack"] == "Collusion"
    assert summary["n_runs"] == 2
    assert summary["AUROC_final"] == 0.95
    assert summary["AUPRC_final"] == 0.9
    assert summary["FPR_h"] == 0.12
    assert summary["n_seeds"] == 2
