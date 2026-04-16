from __future__ import annotations

import json
import math

import pytest

from evaluation.export.experiment_aggregator import ExperimentAggregator, benjamini_hochberg


def _k(name: str) -> tuple[str, str, str]:
    return ("scenario", "variant", name)


def test_benjamini_hochberg_matches_standard_adjustment() -> None:
    p_values = {
        _k("a"): 0.001,
        _k("b"): 0.01,
        _k("c"): 0.02,
    }

    adjusted = benjamini_hochberg(p_values)

    assert adjusted[_k("a")] == pytest.approx(0.003)
    assert adjusted[_k("b")] == pytest.approx(0.015)
    assert adjusted[_k("c")] == pytest.approx(0.02)


def test_benjamini_hochberg_preserves_keys_and_marks_non_finite() -> None:
    p_values = {
        _k("finite_high"): 0.6,
        _k("finite_low"): 0.04,
        _k("nan"): float("nan"),
    }

    adjusted = benjamini_hochberg(p_values)

    assert set(adjusted) == set(p_values)
    assert adjusted[_k("finite_low")] >= p_values[_k("finite_low")]
    assert adjusted[_k("finite_high")] >= p_values[_k("finite_high")]
    assert math.isnan(adjusted[_k("nan")])


def test_aggregator_includes_pmfa_auc_metrics_in_aggregate(tmp_path) -> None:
    aggregator = ExperimentAggregator(output_dir=tmp_path)
    aggregator.add_run(
        {
            "scenario": "pmfa",
            "variant": "full",
            "algo": "three_level_challenge",
            "seed": 1,
            "AUROC_final": 0.9,
            "pmfa_auc_baseline_no_privacy": 0.81,
            "pmfa_auc_legacy_dmpo": 0.72,
            "pmfa_auc_dmpo_x": 0.63,
        },
        run_dir=tmp_path / "run_1",
    )

    outputs = aggregator.finalize()
    aggregate = outputs["aggregate"]

    for metric, expected in {
        "pmfa_auc_baseline_no_privacy": 0.81,
        "pmfa_auc_legacy_dmpo": 0.72,
        "pmfa_auc_dmpo_x": 0.63,
    }.items():
        row = aggregate.loc[aggregate["metric"] == metric]
        assert not row.empty
        assert row.iloc[0]["mean"] == pytest.approx(expected)


def test_aggregator_writes_batch_manifest_and_attribution_metrics(tmp_path) -> None:
    aggregator = ExperimentAggregator(
        output_dir=tmp_path,
        batch_id="batch-123",
        aggregation_scope="current_batch_records_only",
    )
    aggregator.add_run(
        {
            "scenario": "pmfa",
            "variant": "full",
            "algo": "three_level_challenge",
            "seed": 7,
            "run_id": "pmfa_v00_r00_seed7__batch-123",
            "AUROC_final": 0.91,
            "fibd_mean": 0.11,
            "split_fail_mean": 0.22,
            "coalcorr_mean": 0.33,
            "apmfa_penalty_mean": 0.24,
            "final_split_fail_penalty_mean": 0.05,
        },
        run_dir=tmp_path / "run_7",
    )

    outputs = aggregator.finalize()
    aggregate = outputs["aggregate"]

    row = aggregate.loc[aggregate["metric"] == "apmfa_penalty_mean"]
    assert not row.empty
    assert row.iloc[0]["mean"] == pytest.approx(0.24)

    manifest = json.loads((tmp_path / "batch_manifest.json").read_text(encoding="utf-8"))
    assert manifest["batch_id"] == "batch-123"
    assert manifest["aggregation_scope"] == "current_batch_records_only"
    assert manifest["n_unique_runs"] == 1
    assert manifest["n_unique_seeds"] == 1

    stats_gate = json.loads((tmp_path / "stats_gate.json").read_text(encoding="utf-8"))
    assert stats_gate["batch_id"] == "batch-123"
    assert stats_gate["aggregation_scope"] == "current_batch_records_only"
