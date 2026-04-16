from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


def build_dataset_from_privacy_events(events: list[dict], output_csv: Path, output_jsonl: Path | None = None) -> Path:
    rows: list[dict[str, Any]] = []
    for event in events:
        policy = event.get("privacy_policy") or {}
        decision = event.get("privacy_policy_decision") or {}
        alias_epoch = event.get("privacy_alias_epoch", event.get("iteration"))
        delay_window_ms = event.get("dmpo_delay_window_ms", policy.get("delay_window_ms", 0.0))
        rows.append(
            {
                "sender_id": event.get("sender_id"),
                "receiver_id": event.get("receiver_id"),
                "iteration": event.get("iteration"),
                "epoch": alias_epoch,
                "alias_scope": event.get("privacy_alias_scope"),
                "alias_epoch": alias_epoch,
                "alias_epoch_rounds": event.get("privacy_alias_epoch_rounds"),
                "policy_id": policy.get("policy_id", event.get("privacy_strategy", "unknown")),
                "privacy_strategy": event.get("privacy_strategy", "unknown"),
                "K_t": policy.get("K_t", event.get("dmpo_variants", 1)),
                "f_t": policy.get("f_t", event.get("dmpo_variants", 1)),
                "ell_t": policy.get("ell_t", "small"),
                "d_t": policy.get("d_t", "exp_low"),
                "r_t": policy.get("r_t", 0.0),
                "delay_ms": event.get("delay_ms", 0.0),
                "delay_window_ms": delay_window_ms,
                "payload_size": event.get("payload_size", 0.0),
                "is_cover": bool(event.get("is_cover", False)),
                "attack_label": int(bool(event.get("is_challenge", False))),
                "attack_type": event.get("attack_type", "unknown"),
                "message_id": event.get("message_id"),
                "stealth_header": event.get("stealth_header"),
                "policy_decision_objective": decision.get("objective"),
                "policy_decision_risk_target": decision.get("risk_target"),
                "policy_decision_candidate_count": decision.get("candidate_count"),
                "policy_decision_selected_K_t": decision.get("selected_K_t"),
                "policy_decision_selected_f_t": decision.get("selected_f_t"),
                "policy_decision_selected_ell_t": decision.get("selected_ell_t"),
                "policy_decision_selected_d_t": decision.get("selected_d_t"),
                "policy_decision_selected_r_t": decision.get("selected_r_t"),
                "policy_decision_severity": decision.get("severity"),
                "policy_decision_trust_score": decision.get("trust_score"),
                "policy_decision_node_load": decision.get("node_load"),
                "policy_decision_attacker_risk": decision.get("attacker_risk"),
                "policy_decision_budget_penalty": decision.get("budget_penalty"),
                "policy_decision_bw_cost": decision.get("bw_cost"),
                "policy_decision_lat_cost_ms": decision.get("lat_cost_ms"),
                "policy_decision_privacy_strength": decision.get("privacy_strength"),
                "policy_decision_selection_mode": decision.get("selection_mode"),
            }
        )

    df = pd.DataFrame(rows)
    if not df.empty:
        grouped = df.groupby(["sender_id", "receiver_id", "iteration"], dropna=False)
        df["burst_count"] = grouped["message_id"].transform("count")
        df["burst_mean"] = grouped["payload_size"].transform("mean").fillna(0.0)
        df["cover_fraction"] = grouped["is_cover"].transform("mean").fillna(0.0)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)

    if output_jsonl is not None:
        output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with output_jsonl.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
    return output_csv
