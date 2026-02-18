from __future__ import annotations

from typing import Optional, Dict, Any
import pandas as pd
import numpy as np


def plot_auc_round(ax, df: pd.DataFrame) -> None:
    ax.clear()
    if df is None or df.empty:
        ax.text(0.5, 0.5, "No AUC data", ha='center', va='center'); return
    if "auc_roc" in df.columns:
        auroc = df["auc_roc"].astype(float)
    elif "auroc" in df.columns:
        auroc = df["auroc"].astype(float)
    else:
        ax.text(0.5, 0.5, "No AUROC column", ha='center', va='center'); return
    ax.plot(df["round"], auroc, label="AUROC")
    if "auc_pr" in df.columns:
        ax.plot(df["round"], df["auc_pr"], label="AUPRC")
    ymax = float(np.nanmax(auroc))
    ymin = float(np.nanmin(auroc))
    ax.set_ylabel("Score"); ax.set_xlabel("Round")
    ax.set_ylim(max(0.0, ymin - 0.02), min(1.02, ymax + 0.02))
    ax.legend()


def plot_trust_gap(ax, df: pd.DataFrame) -> None:
    ax.clear()
    if df is None or df.empty:
        ax.text(0.5, 0.5, "No Trust Gap data", ha='center', va='center')
        return
    honest_col = 'mean_honest' if 'mean_honest' in df.columns else 'honest_trust'
    malicious_col = 'mean_malicious' if 'mean_malicious' in df.columns else 'malicious_trust'
    ax.plot(df["round"], df[honest_col], label="Honest")
    ax.plot(df["round"], df[malicious_col], label="Malicious")
    if "gap" in df.columns:
        ax2 = ax.twinx()
        ax2.plot(df["round"], df["gap"], color="gray", linestyle="--", label="Gap")
        ax2.set_ylabel("Gap")
    ax.set_xlabel("Round")
    ax.set_ylim(0.0, 1.0)
    ax.legend(loc='upper left')


def plot_tti(ax, df: pd.DataFrame) -> None:
    ax.clear()
    if df is None or df.empty:
        ax.text(0.5, 0.5, "No TTI data", ha='center', va='center')
        return
    if 'is_malicious' in df.columns:
        sub = df[df["is_malicious"] == 1]
    else:
        sub = df
    if sub.empty:
        ax.text(0.5, 0.5, "No malicious nodes detected", ha='center', va='center')
        return
    ax.bar(sub['node_id'].astype(int), sub['tti'].astype(int))
    ax.set_xlabel("Node ID")
    ax.set_ylabel("Detection Round")


def plot_fp_curve(ax, df: pd.DataFrame, tau: float) -> None:
    ax.clear()
    if df is None or df.empty:
        ax.text(0.5, 0.5, "No FP/FN data", ha='center', va='center'); return
    ax.plot(df["round"], df["fp_rate"], label=f"FP rate @ tau={tau}")
    ax.plot(df["round"], df["fn_rate"], label=f"FN rate @ tau={tau}")
    ymax = float(np.nanmax(np.array([df["fp_rate"].max(), df["fn_rate"].max()]))) if len(df) else 0.0
    ax.set_ylim(-0.02, min(1.02, ymax + 0.05))
    ax.set_xlabel("Round"); ax.set_ylabel("Rate"); ax.legend()


def plot_overhead(ax, df: Optional[pd.DataFrame]) -> None:
    ax.clear()
    if df is None or df.empty:
        ax.text(0.5, 0.5, "No Overhead data", ha='center', va='center')
        return
    if "msgs" in df.columns:
        ax.plot(df["round"], df["msgs"], label="Messages")
    if "bytes" in df.columns:
        ax.plot(df["round"], df["bytes"], label="Bytes")
    if "latency_ms_mean" in df.columns:
        ax.plot(df["round"], df["latency_ms_mean"], label="Latency (ms)")
    if all(col not in df.columns for col in ["msgs", "bytes", "latency_ms_mean"]):
        ax.text(0.5, 0.5, "No known overhead columns", ha='center', va='center')
        return
    ax.set_xlabel("Round")
    ax.set_ylabel("Value")
    ax.legend()


def plot_leakage(ax, df_seed: Optional[pd.DataFrame]) -> None:
    ax.clear()
    if df_seed is None or df_seed.empty:
        ax.text(0.5, 0.5, "PMFA leakage only. No data.", ha='center', va='center')
        return
    # Expect columns: auc_no_dmpo, auc_dmpo, delta_auc (optionally seed)
    bars = []
    if "auc_no_dmpo" in df_seed.columns:
        bars.append(("AUC No-DMPO", float(df_seed["auc_no_dmpo"].iloc[0])))
    if "auc_dmpo" in df_seed.columns:
        bars.append(("AUC DMPO", float(df_seed["auc_dmpo"].iloc[0])))
    if not bars:
        ax.text(0.5, 0.5, "No Leakage AUC data", ha='center', va='center')
        return
    labels = [b[0] for b in bars]
    vals = [b[1] for b in bars]
    ax.bar(labels, vals, color=['#888', '#1f77b4'])
    if "delta_auc" in df_seed.columns:
        da = float(df_seed["delta_auc"].iloc[0])
        ax.set_title(f"ΔAUC = {da:.3f}")
    ax.set_ylim(0.0, 1.0)


def plot_stability(ax, df: Optional[pd.DataFrame]) -> None:
    ax.clear()
    if df is None or df.empty:
        ax.text(0.5, 0.5, "No Stability data", ha='center', va='center'); return
    ax.plot(df['round'], df['kendall_tau'], marker='o', label='Kendall τ')
    ax.set_ylim(-1.05, 1.05)
    ax.set_xlabel('Round')
    ax.set_ylabel('Kendall τ')
    ax.grid(True, alpha=0.3)


def plot_pmfa_success(ax, summary: Dict[str, Any]) -> None:
    ax.clear()
    if not summary:
        ax.text(0.5, 0.5, "No summary available", ha='center', va='center'); return
    no_ver = summary.get('pmfa_success_rate_no_ver')
    with_ver = summary.get('pmfa_success_rate_with_ver')
    if not np.isfinite(no_ver) and not np.isfinite(with_ver):
        ax.text(0.5, 0.5, "No PMFA metrics", ha='center', va='center'); return
    labels = []
    values = []
    if np.isfinite(no_ver):
        labels.append('No Verification')
        values.append(no_ver)
    if np.isfinite(with_ver):
        labels.append('With Verification')
        values.append(with_ver)
    ax.bar(labels, values, color=['#d62728', '#2ca02c'][:len(labels)])
    ax.set_ylim(0, 1)
    ax.set_ylabel('Success rate')
