from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Tuple
from tkinter import ttk


CARD_SPECS: List[Tuple[str, Tuple[str, ...]]] = [
    ("AUROC Final", ("AUROC_final", "auroc_final", "auc_final")),
    ("AUROC Mean", ("AUROC_mean", "auroc_mean")),
    ("AUPR Final", ("AUPR_final", "aupr_final", "auc_pr_final")),
    ("Precision", ("precision_final", "precision")),
    ("Recall", ("recall_final", "recall", "detection_rate")),
    ("F1 Score", ("f1_final", "f1_score")),
    ("FP Rate", ("false_positive_rate", "fp_final", "FPR_h")),
    ("FN Rate", ("fn_final", "FNR_m")),
    ("ASR", ("asr", "bypass_rate")),
    ("FQR", ("fqr",)),
    ("FNRQ", ("fnrq",)),
    ("TTD Median", ("TTD_median", "tti_median")),
    ("TTD Q1–Q3", ("TTD_q1_q3_str",)),
    ("TTD 95% CI", ("TTD_ci_str",)),
    ("TTD IQR", ("TTD_iqr", "tti_iqr")),
    ("Messages/Round", ("msgs_per_round_mean", "overhead_mean")),
    ("Latency Mean (ms)", ("latency_ms_mean", "latency_per_round_mean")),
    ("Trust Gap Final", ("trust_gap_final", "trust_gap")),
    ("Trust Gap AUC", ("trust_gap_auc",)),
    ("Stability τ", ("stability_kendall_tau",)),
    ("PMFA CW Acc (No Ver)", ("pmfa_success_rate_baseline_no_privacy", "pmfa_success_rate_no_ver")),
    ("PMFA CW Acc (With Ver)", ("pmfa_success_rate_legacy_dmpo", "pmfa_success_rate_with_ver")),
    ("PMFA CW Acc (DMPO-X)", ("pmfa_success_rate_dmpo_x",)),
]


def render_kpi_cards(parent, summary: Dict[str, Any]) -> None:
    """Render KPI cards using summary values."""
    for child in parent.winfo_children():
        child.destroy()

    cards = [(label, _fmt(_lookup(summary, aliases))) for label, aliases in CARD_SPECS]
    if not cards:
        return

    frame = ttk.Frame(parent)
    frame.pack(fill="x", padx=6, pady=6)

    cols = min(4, max(1, int(len(cards) ** 0.5) + 1))
    for col in range(cols):
        frame.columnconfigure(col, weight=1)

    for index, (label, value) in enumerate(cards):
        card = ttk.Frame(frame, padding=(10, 8), relief="groove")
        card.grid(row=index // cols, column=index % cols, padx=4, pady=4, sticky="nsew")
        ttk.Label(card, text=label, font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
        ttk.Label(card, text=value, font=("TkDefaultFont", 11)).pack(anchor="w")


def _lookup(summary: Dict[str, Any], aliases: Iterable[str]) -> Any:
    for key in aliases:
        if key in summary:
            value = summary[key]
            if isinstance(value, float) and math.isnan(value):
                continue
            return value
    return None


def _fmt(value: Any) -> str:
    try:
        if value is None:
            return "–"
        if isinstance(value, (int, float)):
            if isinstance(value, float) and math.isnan(value):
                return "–"
            if 0 <= value <= 1:
                return f"{value:.3f}"
            return f"{value:.2f}"
        return str(value)
    except Exception:
        return "–"
