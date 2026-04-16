from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from evaluation.pipeline.run_evaluator import RunEvaluator


def test_build_summary_emits_eval2_framing_metadata(tmp_path: Path) -> None:
    evaluator = RunEvaluator.__new__(RunEvaluator)
    evaluator.inputs = SimpleNamespace(
        scenario_id="pmfa",
        variant_label="full",
        run_id="run-1",
        method="three_level_challenge",
        attack_type="pmfa",
        topology="random",
        n_nodes=20,
        seed=42,
        fraction_colluders=0.1,
        fraction_sybils=0.0,
        malicious_ratio=0.2,
        trust_threshold=0.6,
        db_path=tmp_path / "run.db",
        config={
            "features": {
                "privacy_strategy": "dmpo_x",
                "privacy": {"strategy": "dmpo_x"},
            }
        },
        runtime_snapshot={
            "privacy_pmfa_logs": [
                {
                    "privacy_strategy": "dmpo_x",
                    "privacy_alias_scope": "recipient_epoch",
                    "privacy_policy_decision": {"selected_policy_id": "p2"},
                }
            ]
        },
    )
    evaluator.outputs_dir = tmp_path
    evaluator.challenge_df = pd.DataFrame(
        [{"fibd": 0.1, "split_fail": 0.2, "coalcorr": 0.3, "apmfa_penalty": 0.2}]
    )

    summary = evaluator._build_summary(
        auc_rounds=pd.DataFrame([{"round": 1, "auroc": 0.9, "auprc": 0.8}]),
        ttd_stats={"median": 2.0, "mean": 2.0, "ci": (2.0, 2.0)},
        auroc_thresholds={},
        collusion_metrics={},
        sybil_metrics={},
        betrayal_metrics={},
        error_rates={
            "fpr_honest": 0.1,
            "fnr_malicious": 0.2,
            "accuracy": 0.8,
            "precision": 0.75,
            "recall": 0.7,
            "f1_score": 0.72,
            "false_positive_rate": 0.1,
        },
        bypass_rate=0.3,
        stability={"variance_mean": 0.01, "kendall_tau_mean": 0.9},
        overhead={"msgs_mean": 10.0, "bytes_mean": 1000.0, "latency_mean": 15.0},
        pmfa_stats={
            "success_baseline_no_privacy": 0.7,
            "success_legacy_dmpo": 0.6,
            "success_dmpo_x": 0.5,
            "auc_baseline_no_privacy": 0.8,
            "auc_legacy_dmpo": 0.7,
            "auc_dmpo_x": 0.6,
            "open_adv_baseline_no_privacy": 0.4,
            "open_adv_legacy_dmpo": 0.3,
            "open_adv_dmpo_x": 0.2,
            "drift_auc_baseline_no_privacy": 0.75,
            "drift_auc_legacy_dmpo": 0.68,
            "drift_auc_dmpo_x": 0.61,
            "eval3_model_baseline_no_privacy": "tree",
            "eval3_model_legacy_dmpo": "logreg",
            "eval3_model_dmpo_x": "temporal",
        },
        attribution_stats={
            "fibd_mean": 0.11,
            "split_fail_mean": 0.22,
            "coalcorr_mean": 0.33,
            "apmfa_penalty_mean": 0.24,
            "apmfa_penalty_mean_malicious": 0.41,
            "final_split_fail_penalty_mean": 0.05,
            "attribution_signal_count_mean": 3.0,
        },
        trust_gap_series=pd.DataFrame([{"round": 1, "gap": 0.1}]),
        extra_metrics={},
    )

    assert summary["pmfa_evidence_scope"] == "eval3_attacker_pipeline_lightweight"
    assert summary["pmfa_model_family"] == "lightweight_tabular_plus_proxy_temporal"
    assert summary["evaluation_scope"] == "eval_2_protocol_simulation"
    assert summary["simulator_label"] == "simpy_hybrid_discrete_event_protocol_simulator"
    assert summary["trust_attribution_scope"] == "explicit_runtime_fibd_splitfail_coalcorr"
    assert summary["dmpo_x_scope"] == "dmpo_x_runtime_eval2_canonical"
    assert summary["pmfa_open_adv_dmpo_x"] == 0.2
    assert summary["pmfa_drift_auc_dmpo_x"] == 0.61
    assert summary["pmfa_best_model_dmpo_x"] == "temporal"
    assert summary["apmfa_penalty_mean"] == 0.24
    assert summary["final_split_fail_penalty_mean"] == 0.05
