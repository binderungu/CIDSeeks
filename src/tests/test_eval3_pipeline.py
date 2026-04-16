from pathlib import Path

import pandas as pd

from eval3_metadata_attacker.dataset_builder import build_dataset_from_privacy_events
from eval3_metadata_attacker.run_closed_world import run as run_closed
from eval3_metadata_attacker.run_open_world import run as run_open
from eval3_metadata_attacker.run_drift import run as run_drift


def _events():
    events = []
    for i in range(30):
        events.append({
            "sender_id": 1,
            "receiver_id": 2,
            "iteration": i,
            "privacy_strategy": "dmpo_x" if i % 2 == 0 else "dmpo_legacy",
            "privacy_policy": {"K_t": 2, "f_t": 3, "r_t": 0.1},
            "delay_ms": float(i + 1),
            "payload_size": 120 + i,
            "is_cover": i % 5 == 0,
            "is_challenge": i % 3 == 0,
            "message_id": f"m-{i}",
            "privacy_alias_scope": "recipient_epoch",
            "privacy_alias_epoch": i // 5,
            "privacy_alias_epoch_rounds": 5,
            "privacy_policy_decision": {
                "selected_policy_id": "px",
                "selected_K_t": 2,
                "selected_f_t": 3,
                "selected_ell_t": "medium",
                "selected_d_t": "exp_mid",
                "selected_r_t": 0.1,
                "objective": 0.1 + (i / 100.0),
                "risk_target": 0.5,
                "candidate_count": 3,
                "severity": 0.7,
                "trust_score": 0.6,
                "node_load": 0.2,
                "attacker_risk": 0.8,
                "budget_penalty": 0.0,
                "bw_cost": 1.5,
                "lat_cost_ms": 120.0,
                "privacy_strength": 0.65,
                "selection_mode": "objective_minimization",
            },
        })
    return events


def test_eval3_runs(tmp_path: Path):
    csv_path = tmp_path / "summary.csv"
    jsonl_path = tmp_path / "seq.jsonl"
    build_dataset_from_privacy_events(_events(), csv_path, jsonl_path)
    df = pd.read_csv(csv_path)

    cw = run_closed(csv_path)
    ow = run_open(csv_path)
    dr = run_drift(csv_path)

    assert "alias_scope" in df.columns
    assert "policy_decision_objective" in df.columns
    assert "policy_decision_candidate_count" in df.columns
    assert df["alias_epoch"].iloc[0] == 0
    assert df["policy_decision_selected_r_t"].iloc[0] == 0.1
    assert df["policy_decision_candidate_count"].iloc[0] == 3
    assert df["policy_decision_selection_mode"].iloc[0] == "objective_minimization"
    assert cw["setting"] == "closed_world"
    assert ow["setting"] == "open_world"
    assert dr["setting"] == "drift"
    assert set(cw["models"].keys()) == {"logreg", "tree", "temporal"}
