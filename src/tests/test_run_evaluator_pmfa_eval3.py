from __future__ import annotations

import json
import math
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from evaluation.pipeline.run_evaluator import RunEvaluator


def _privacy_logs() -> list[dict]:
    logs: list[dict] = []
    strategies = [
        ("baseline_no_privacy", False, {"policy_id": "base", "K_t": 1, "f_t": 1, "r_t": 0.0}),
        ("legacy_dmpo", True, {"policy_id": "p1", "K_t": 3, "f_t": 3, "r_t": 0.1}),
        ("dmpo_x", True, {"policy_id": "p2", "K_t": 4, "f_t": 2, "r_t": 0.2}),
    ]
    iteration = 0
    for strategy, enabled, policy in strategies:
        for idx in range(24):
            is_challenge = idx % 2 == 0
            logs.append(
                {
                    "sender_id": 1 + (idx % 3),
                    "receiver_id": 10 + (idx % 5),
                    "iteration": iteration,
                    "event_scope": "wire",
                    "dmpo_enabled": enabled,
                    "privacy_strategy": strategy,
                    "privacy_policy": policy,
                    "delay_ms": float(40 + idx if is_challenge else 4 + idx),
                    "payload_size": float(180 + idx if is_challenge else 90 + idx),
                    "is_cover": bool(idx % 6 == 0),
                    "is_challenge": is_challenge,
                    "message_id": f"{strategy}-m-{idx}",
                    "stealth_header": f"sh1:{strategy}-{idx}",
                    "privacy_alias_scope": "recipient_epoch" if strategy == "dmpo_x" else None,
                    "privacy_alias_epoch": idx // 4 if strategy == "dmpo_x" else None,
                    "privacy_alias_epoch_rounds": 4 if strategy == "dmpo_x" else None,
                    "privacy_policy_decision": {
                        "selected_policy_id": policy["policy_id"],
                        "selected_K_t": policy["K_t"],
                        "selected_f_t": policy["f_t"],
                        "selected_ell_t": "medium",
                        "selected_d_t": "exp_mid",
                        "selected_r_t": policy["r_t"],
                        "objective": 0.25,
                        "risk_target": 0.55,
                        "candidate_count": 3,
                        "severity": 0.8,
                        "trust_score": 0.6,
                        "node_load": 0.2,
                        "attacker_risk": 0.9,
                        "budget_penalty": 0.0,
                        "bw_cost": 1.8,
                        "lat_cost_ms": 150.0,
                        "privacy_strength": 0.7,
                        "selection_mode": "objective_minimization",
                    } if strategy == "dmpo_x" else None,
                }
            )
            iteration += 1
    return logs


def test_compute_pmfa_stats_emits_eval3_artifacts(tmp_path: Path) -> None:
    evaluator = RunEvaluator.__new__(RunEvaluator)
    evaluator.inputs = SimpleNamespace(
        attack_type="PMFA",
        runtime_snapshot={"privacy_pmfa_logs": _privacy_logs()},
        seed=7,
    )
    evaluator.outputs_dir = tmp_path

    stats = evaluator._compute_pmfa_stats()

    for label in ("baseline_no_privacy", "legacy_dmpo", "dmpo_x"):
        assert 0.0 <= float(stats[f"success_{label}"]) <= 1.0
        assert 0.0 <= float(stats[f"auc_{label}"]) <= 1.0
        assert 0.0 <= float(stats[f"open_adv_{label}"]) <= 1.0
        assert 0.0 <= float(stats[f"drift_auc_{label}"]) <= 1.0
        assert stats[f"eval3_model_{label}"] in {"logreg", "tree", "temporal"}

        dataset_csv = tmp_path / "eval3_pmfa" / f"{label}_dataset.csv"
        closed_world_json = tmp_path / "eval3_pmfa" / f"{label}_closed_world.json"
        open_world_json = tmp_path / "eval3_pmfa" / f"{label}_open_world.json"
        drift_json = tmp_path / "eval3_pmfa" / f"{label}_drift.json"

        assert dataset_csv.exists()
        assert closed_world_json.exists()
        assert open_world_json.exists()
        assert drift_json.exists()

        dataset_df = pd.read_csv(dataset_csv)
        assert "alias_scope" in dataset_df.columns
        assert "policy_decision_objective" in dataset_df.columns
        assert "policy_decision_candidate_count" in dataset_df.columns
        if label == "dmpo_x":
            assert dataset_df["alias_scope"].dropna().eq("recipient_epoch").all()
            assert dataset_df["policy_decision_candidate_count"].dropna().eq(3).all()
            assert dataset_df["policy_decision_selected_r_t"].dropna().eq(0.2).all()
            assert dataset_df["policy_decision_selection_mode"].dropna().eq("objective_minimization").all()

        closed_world = json.loads(closed_world_json.read_text(encoding="utf-8"))
        assert closed_world["setting"] == "closed_world"
        assert closed_world["dataset_rows"] == 24
        assert closed_world["random_state"] == 7


def test_compute_pmfa_stats_is_nan_for_non_pmfa_runs(tmp_path: Path) -> None:
    evaluator = RunEvaluator.__new__(RunEvaluator)
    evaluator.inputs = SimpleNamespace(
        attack_type="Collusion",
        runtime_snapshot={"privacy_pmfa_logs": _privacy_logs()},
        seed=11,
    )
    evaluator.outputs_dir = tmp_path

    stats = evaluator._compute_pmfa_stats()

    assert math.isnan(float(stats["success_baseline_no_privacy"]))
    assert math.isnan(float(stats["auc_dmpo_x"]))
    assert stats["eval3_model_dmpo_x"] is None
    assert not (tmp_path / "eval3_pmfa").exists()
