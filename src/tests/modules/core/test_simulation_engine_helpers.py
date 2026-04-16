from __future__ import annotations

import json
import logging
import math
from pathlib import Path

import pandas as pd

from simulation.core.simulation_engine import SimulationEngine


def _engine_stub() -> SimulationEngine:
    engine = object.__new__(SimulationEngine)
    engine.logger = logging.getLogger("test.simulation_engine.helpers")
    engine.config = {}
    engine.attack_type = "Collusion"
    engine.total_nodes = 30
    return engine


def test_sanitize_run_token_normalizes_and_falls_back() -> None:
    assert SimulationEngine._sanitize_run_token("  Run Alpha/01  ") == "run-alpha-01"
    assert SimulationEngine._sanitize_run_token("__") == "run"
    assert SimulationEngine._sanitize_run_token(None) == "run"


def test_safe_float_and_sanitize_payload_value_handle_non_finite() -> None:
    assert SimulationEngine._safe_float("1.25") == 1.25
    assert SimulationEngine._safe_float(float("nan")) is None
    assert SimulationEngine._safe_float(float("inf")) is None
    assert SimulationEngine._safe_float("bad") is None

    assert SimulationEngine._sanitize_payload_value(3) == 3
    assert SimulationEngine._sanitize_payload_value("ok") == "ok"
    assert SimulationEngine._sanitize_payload_value(True) is True
    assert SimulationEngine._sanitize_payload_value(None) is None
    assert SimulationEngine._sanitize_payload_value(1.23456789) == 1.234568
    assert SimulationEngine._sanitize_payload_value(float("nan")) is None

    class _Weird:
        def __str__(self) -> str:
            return "weird-value"

    assert SimulationEngine._sanitize_payload_value(_Weird()) == "weird-value"


def test_sha256_and_epoch_helpers_are_deterministic() -> None:
    expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert SimulationEngine._sha256_bytes(b"hello") == expected
    assert SimulationEngine._epoch_to_iso8601(0.0) == "1970-01-01T00:00:00Z"
    assert SimulationEngine._epoch_to_iso8601(None) is None
    assert SimulationEngine._epoch_to_iso8601("bad") is None


def test_compute_event_payload_bytes_counts_messages_for_each_stage() -> None:
    event = {
        "node_id": 1,
        "related_node_id": 2,
        "iteration": 7,
        "details": {
            "prev_trust": 0.9,
            "total_trust": 0.1,
            "detection_threshold": 0.5,
            "target_is_malicious": True,
            "basic": 0.2,
            "advanced": 0.3,
            "final": 0.4,
            "reputation": 0.6,
            "contribution": 0.7,
            "penalty": 0.1,
            "auth": 1.0,
            "biometric_score": 0.8,
        },
    }

    stats = SimulationEngine._compute_event_payload_bytes(event, default_latency_ms=123.0)
    assert stats["messages"] == 6.0
    assert stats["bytes"] > 0.0
    assert stats["latency_ms"] == 123.0


def test_compute_event_payload_bytes_handles_missing_scores_and_weird_values() -> None:
    event = {
        "node_id": 0,
        "related_node_id": 1,
        "iteration": 1,
        "details": {
            "basic": "not-a-number",
            "advanced": None,
            "final": float("nan"),
            "prev_trust": object(),  # falls back to None via _safe_float
        },
    }
    stats = SimulationEngine._compute_event_payload_bytes(event, default_latency_ms=50.0)
    assert stats == {"messages": 0.0, "bytes": 0.0, "latency_ms": 50.0}


def test_estimate_overhead_from_events_aggregates_per_round(tmp_path: Path) -> None:
    engine = _engine_stub()
    engine.config = {"simulation": {"update_interval": 0.25}}
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    events_path = run_dir / "events.jsonl"

    records = [
        {
            "event_type": "challenge_outcome",
            "iteration": 1,
            "node_id": 1,
            "related_node_id": 2,
            "details": {"basic": 0.1, "advanced": 0.2, "final": 0.3},
        },
        {
            "event_type": "challenge_outcome",
            "iteration": 1,
            "node_id": 2,
            "related_node_id": 3,
            "details": {"basic": 0.4},
        },
        {
            "event_type": "other_event",
            "iteration": 1,
            "node_id": 9,
            "related_node_id": 9,
            "details": {},
        },
        {
            "event_type": "challenge_outcome",
            "iteration": 2,
            "node_id": 4,
            "related_node_id": 5,
            "details": {"basic": 0.2, "advanced": 0.5},
        },
    ]
    events_path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    result = engine._estimate_overhead_from_events(run_dir)
    assert result is not None

    per_round = result["per_round"]
    assert isinstance(per_round, pd.DataFrame)
    assert list(per_round["round"]) == [1.0, 2.0]
    assert list(per_round["msgs"]) == [8.0, 4.0]  # 6+2 messages in round 1, 4 in round 2
    assert all(per_round["bytes"] > 0.0)
    assert list(per_round["latency_ms_mean"]) == [250.0, 250.0]
    assert math.isclose(result["msgs_mean"], 6.0, rel_tol=0, abs_tol=1e-9)
    assert result["bytes_mean"] == float(per_round["bytes"].mean())
    assert result["latency_mean"] == 250.0


def test_estimate_overhead_from_events_handles_missing_or_invalid_file(tmp_path: Path) -> None:
    engine = _engine_stub()
    engine.config = {"simulation": {"update_interval": 0.1}}

    missing_dir = tmp_path / "missing"
    missing_dir.mkdir()
    assert engine._estimate_overhead_from_events(missing_dir) is None

    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    (bad_dir / "events.jsonl").write_text("{not-json}\n", encoding="utf-8")
    assert engine._estimate_overhead_from_events(bad_dir) is None


def test_derive_variant_label_includes_attack_and_optional_ratios() -> None:
    engine = _engine_stub()
    engine.config = {
        "trust_model": {"method": "3-level-challenge", "forgetting_factor": 0.9},
        "attack": {"collusion_ratio": 0.15, "sybil_ratio": 0.2},
    }
    engine.attack_type = "Sybil"
    engine.total_nodes = 128

    label = engine._derive_variant_label()
    assert label == "3-level-challenge_attack-sybil_N128_coll0.15_syb0.20_lambda0.90"


def test_derive_variant_label_uses_lambda_fallback_key() -> None:
    engine = _engine_stub()
    engine.config = {
        "trust_model": {"method": "ours", "lambda": 0.75},
        "attack": {},
    }
    engine.attack_type = None
    engine.total_nodes = 10

    label = engine._derive_variant_label()
    assert label == "ours_attack-generic_N10_lambda0.75"


def test_refresh_suite_aggregates_skips_attack_summary_when_columns_missing(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    from evaluation.export import experiment_aggregator as aggregator_module

    class _DummyAggregator:
        def __init__(
            self,
            output_dir: Path,
            bootstrap_samples: int,
            seed: int,
            batch_id: str | None = None,
            aggregation_scope: str = "current_batch_records_only",
        ) -> None:
            self.output_dir = output_dir
            self.bootstrap_samples = bootstrap_samples
            self.seed = seed
            self.batch_id = batch_id
            self.aggregation_scope = aggregation_scope
            self.run_log_path = output_dir / "run_log.json"
            self.records = []

        def finalize(self) -> None:
            return None

    monkeypatch.setattr(aggregator_module, "ExperimentAggregator", _DummyAggregator)

    engine = _engine_stub()
    engine.output_root = tmp_path
    engine.suite = "smoke"
    engine.seed = 123
    engine.config = {"simulation": {"update_interval": 0.1}}

    suite_root = tmp_path / "smoke"
    run_dir = suite_root / "run-1"
    run_dir.mkdir(parents=True)
    pd.DataFrame([{"AUROC_final": 0.91}]).to_csv(run_dir / "summary.csv", index=False)

    with caplog.at_level(logging.WARNING):
        engine._refresh_suite_aggregates()

    assert not (suite_root / "attack_summary.csv").exists()
    assert "Failed to refresh scenario aggregates" not in caplog.text
