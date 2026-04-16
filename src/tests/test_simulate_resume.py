from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

import simulate


def _write_run_artifact(
    run_dir: Path,
    *,
    experiment_id: str,
    run_id: str,
    seed: int = 42,
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        [
            {
                "scenario": "demo",
                "variant": "v0",
                "algo": "ours",
                "seed": seed,
                "run_id": run_id,
                "AUROC_final": 0.9,
            }
        ]
    ).to_csv(run_dir / "summary.csv", index=False)
    (run_dir / "metadata.json").write_text(
        json.dumps(
            {
                "suite": "smoke",
                "experiment_id": experiment_id,
                "run_id": run_id,
                "seed": seed,
            }
        ),
        encoding="utf-8",
    )


def test_parse_args_supports_resume_and_rejects_overwrite_conflict() -> None:
    args = simulate.parse_args(["--suite", "smoke", "--config", "x.yaml", "--resume"])
    assert args.resume is True
    assert args.overwrite is False

    with pytest.raises(SystemExit):
        simulate.parse_args(["--suite", "smoke", "--config", "x.yaml", "--resume", "--overwrite"])


def test_find_resumable_run_uses_latest_complete_artifact(tmp_path: Path) -> None:
    output_root = tmp_path / "results" / "smoke"
    experiment_id = "scenario_v00_r00_seed42"
    older = output_root / f"{experiment_id}__20260101T000000000000Z_v00_r00_seed42"
    newer = output_root / f"{experiment_id}__20260102T000000000000Z_v00_r00_seed42"
    _write_run_artifact(older, experiment_id=experiment_id, run_id=older.name, seed=42)
    _write_run_artifact(newer, experiment_id=experiment_id, run_id=newer.name, seed=43)

    resumed = simulate._find_resumable_run(output_root, experiment_id=experiment_id)

    assert resumed is not None
    summary_row, run_dir = resumed
    assert Path(run_dir) == newer
    assert int(summary_row["seed"]) == 43


def test_find_resumable_run_rejects_incomplete_artifact(tmp_path: Path) -> None:
    output_root = tmp_path / "results" / "smoke"
    experiment_id = "scenario_v00_r00_seed42"
    broken = output_root / f"{experiment_id}__20260101T000000000000Z_v00_r00_seed42"
    broken.mkdir(parents=True, exist_ok=True)
    (broken / "summary.csv").write_text("run_id,seed\nx,1\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        simulate._find_resumable_run(output_root, experiment_id=experiment_id)


def test_apply_variant_syncs_dmpox_nested_privacy_config() -> None:
    cfg = simulate._apply_variant(
        base={
            "simulation": {},
            "features": {
                "privacy_strategy": "dmpo_legacy",
                "privacy": {
                    "strategy": "dmpo_legacy",
                    "alias_epoch_rounds": 5,
                    "controller": {"enabled": False},
                },
                "ablations": {
                    "fibd": True,
                    "split_fail": True,
                    "coalcorr": True,
                },
            },
        },
        variant={
            "privacy_strategy": "dmpo_x",
            "privacy_alias_epoch_rounds": 7,
            "attribution_profile": "no_split_fail",
            "final_split_fail_weight": 0.4,
        },
        scenario={"scenario_id": "demo", "attack_type": "PMFA"},
        seed=7,
        experiment_id="exp-7",
        run_uid="run-7",
    )

    features = cfg["features"]
    assert features["privacy_strategy"] == "dmpo_x"
    assert features["privacy"]["strategy"] == "dmpo_x"
    assert features["privacy"]["alias_epoch_rounds"] == 7
    assert features["privacy"]["controller"]["enabled"] is True
    assert features["ablations"]["fibd"] is True
    assert features["ablations"]["split_fail"] is False
    assert features["ablations"]["coalcorr"] is True
    assert features["attribution"]["final_split_fail_weight"] == 0.4


def test_run_scenarios_resume_skips_engine_and_aggregates_existing_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_config_path = tmp_path / "base_config.yaml"
    base_config_path.write_text(
        "\n".join(
            [
                "simulation:",
                "  total_nodes: 10",
                "  iterations: 5",
                "trust_model:",
                "  method: three_level_challenge",
                "attack:",
                "  type: PMFA",
                "features: {}",
                "output: {}",
            ]
        ),
        encoding="utf-8",
    )

    suite_root = tmp_path / "results" / "smoke"
    experiment_id = "smoke_demo_v00_r00_seed123"
    existing_run = suite_root / f"{experiment_id}__20260101T000000000000Z_v00_r00_seed123"
    _write_run_artifact(existing_run, experiment_id=experiment_id, run_id=existing_run.name, seed=123)

    config = {
        "base_config": str(base_config_path),
        "runs_per_variant": 1,
        "seed_start": 123,
        "scenarios": [
            {
                "scenario_id": "smoke_demo",
                "attack_type": "PMFA",
                "parameters": {},
            }
        ],
        "stats_gate": {"enforce": False},
    }

    monkeypatch.setattr(simulate, "_suite_output_root", lambda suite: suite_root)
    monkeypatch.setattr(simulate, "_generate_suite_plots", lambda *_args, **_kwargs: None)

    class FakeAgg:
        instances: list["FakeAgg"] = []

        def __init__(self, *args, **kwargs):
            self.records = []
            FakeAgg.instances.append(self)

        def add_run(self, summary_row, run_dir):
            self.records.append((summary_row, run_dir))

        def finalize(self):
            # Create minimal file so post-finalize read path exists.
            out_dir = suite_root
            out_dir.mkdir(parents=True, exist_ok=True)
            pd.DataFrame([r[0] for r in self.records]).to_csv(out_dir / "experiments.csv", index=False)
            return {}

    monkeypatch.setattr(simulate, "ExperimentAggregator", FakeAgg)

    class FailEngine:
        def __init__(self, *args, **kwargs):
            raise AssertionError("SimulationEngine should not be instantiated when --resume finds a run")

    monkeypatch.setattr(simulate, "SimulationEngine", FailEngine)

    simulate.run_scenarios(config, "smoke", config_path=str(tmp_path / "suite.yaml"), resume=True)

    assert FakeAgg.instances, "Aggregator was not instantiated"
    assert len(FakeAgg.instances[0].records) == 1
    resumed_summary, resumed_dir = FakeAgg.instances[0].records[0]
    assert int(resumed_summary["seed"]) == 123
    assert Path(resumed_dir) == existing_run
