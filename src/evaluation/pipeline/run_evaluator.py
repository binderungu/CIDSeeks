"""Run-level evaluation pipeline for CIDSeeks simulations.

This module derives academically grounded metrics from raw simulation
artifacts (trust evolution, database traces, runtime telemetry) and
materialises the deliverables expected by the dissertation guidelines:

- summary.csv          – single-row table containing per-run headline metrics
- metrics_per_round.csv – AUROC, overhead, stability traces
- events.jsonl          – structured event log (challenge, alarms, actions)
- plots/*.png           – AUROC vs time, TTD CDF, overhead, PMFA success, stability

The evaluator operates purely on data emitted by the simulation engine:
  * `EnhancedMetrics` (trust_evolution, challenge outcomes, runtime stats)
  * `metric_logger` snapshot (message telemetry, PMFA observations)
  * SQLite database (events, trust_scores, metadata)

Statistical descriptors (95% CI via bootstrap) are provided at run scope.
Scenario-level aggregation and significance testing are handled separately
by :mod:`evaluation.export.experiment_aggregator`.
"""

from __future__ import annotations

import json
import math
import sqlite3
import shutil
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

from ..metrics.enhanced_metrics import EnhancedMetrics, compute_auprc, compute_trust_gap_auc
from simulation.utils.rng import make_numpy_rng


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _safe_auc(labels: Sequence[int], trust_scores: Sequence[float]) -> float:
    if not labels:
        return float('nan')
    y_true = np.asarray(labels, dtype=int)
    scores = np.asarray(trust_scores, dtype=float)
    if np.unique(y_true).size < 2:
        return float('nan')
    try:
        malicious_prob = 1.0 - scores
        return float(roc_auc_score(y_true, malicious_prob))
    except Exception:
        return float('nan')


def _bootstrap_ci(
    values: Sequence[float],
    func=np.mean,
    ci: float = 0.95,
    resamples: int = 10000,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[float, float]:
    arr = np.asarray([float(v) for v in values if math.isfinite(float(v))], dtype=float)
    if arr.size == 0:
        return float('nan'), float('nan')
    if arr.size == 1:
        val = float(func(arr))
        return val, val
    rng = rng or make_numpy_rng(0, "run_evaluator_bootstrap_ci")
    samples = []
    for _ in range(max(1, resamples)):
        try:
            resample = rng.choice(arr, size=arr.size, replace=True)
            samples.append(float(func(resample)))
        except Exception:
            continue
    if not samples:
        return float('nan'), float('nan')
    alpha = (1.0 - ci) / 2.0
    return (
        float(np.percentile(samples, alpha * 100.0)),
        float(np.percentile(samples, (1.0 - alpha) * 100.0)),
    )


def _kendall_tau(prev_vec: np.ndarray, next_vec: np.ndarray) -> float:
    mask = np.isfinite(prev_vec) & np.isfinite(next_vec)
    if mask.sum() < 2:
        return float('nan')
    tau, _ = stats.kendalltau(prev_vec[mask], next_vec[mask])
    return float(tau) if tau is not None else float('nan')


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class RunEvaluationInputs:
    run_id: str
    scenario_id: str
    variant_label: str
    method: str
    attack_type: str
    topology: str
    n_nodes: int
    fraction_colluders: float
    fraction_sybils: float
    malicious_ratio: float
    seed: int
    trust_threshold: float
    config: Mapping[str, Any]
    enhanced_metrics: EnhancedMetrics
    runtime_snapshot: Mapping[str, Any]
    db_path: Path
    output_dir: Path


@dataclass
class RunEvaluationResult:
    summary_row: Dict[str, Any]
    per_round_metrics: pd.DataFrame
    overhead_per_round: pd.DataFrame
    stability_per_round: pd.DataFrame
    pmfa_stats: Dict[str, Any]
    figures: Dict[str, Path]


class RunEvaluator:
    """Compute run-level metrics and persist evaluation artifacts."""

    def __init__(self, inputs: RunEvaluationInputs) -> None:
        self.inputs = inputs
        self.outputs_dir = _ensure_dir(inputs.output_dir)
        self.fig_dir = _ensure_dir(self.outputs_dir / "figures")
        legacy_fig_dir = self.outputs_dir / "fig"
        if legacy_fig_dir.exists():
            shutil.rmtree(legacy_fig_dir, ignore_errors=True)
        self.rng = make_numpy_rng(inputs.seed, "run_evaluator")
        self.logger = logging.getLogger("RunEvaluator")

        self.trust_df = self._prepare_trust_dataframe()
        self.challenge_df = self._prepare_challenge_dataframe()
        self.message_df = self._prepare_message_dataframe()

    # -- preparation -----------------------------------------------------
    def _prepare_trust_dataframe(self) -> pd.DataFrame:
        data = pd.DataFrame(self.inputs.enhanced_metrics.trust_evolution)
        if data.empty:
            return data
        data = data.rename(columns={'iteration': 'round'})
        data['round'] = data['round'].astype(int)
        data['node_id'] = data['node_id'].astype(int)
        data['trust_score'] = data['trust_score'].astype(float)
        data['is_malicious'] = data['is_malicious'].astype(bool)
        return data.sort_values(['round', 'node_id'])

    def _prepare_challenge_dataframe(self) -> pd.DataFrame:
        data = pd.DataFrame(self.inputs.enhanced_metrics.challenge_outcomes)
        if data.empty:
            return data
        data = data.rename(columns={'iteration': 'round'})
        data['round'] = data['round'].astype(int)
        data['source_node'] = data['source_node'].astype(int)
        data['target_node'] = data['target_node'].astype(int)
        data['trust_before'] = data['trust_before'].astype(float)
        data['trust_after'] = data['trust_after'].astype(float)
        data['detection_threshold'] = data['detection_threshold'].astype(float)
        data['target_is_malicious'] = data['target_is_malicious'].astype(bool)
        return data.sort_values(['round', 'source_node', 'target_node'])

    def _prepare_message_dataframe(self) -> pd.DataFrame:
        data = pd.DataFrame(self.inputs.runtime_snapshot.get('message_events', []))
        if data.empty:
            return data
        data['round'] = data['iteration'].astype(int)
        data['payload_bytes'] = data['payload_bytes'].astype(float)
        if 'latency_ms' not in data.columns:
            data['latency_ms'] = np.nan
        return data

    def _round_duration_seconds(self) -> float:
        """Return simulated duration (seconds) of a single round."""
        sim_cfg = self.inputs.config.get('simulation', {}) if isinstance(self.inputs.config, Mapping) else {}
        try:
            return float(sim_cfg.get('update_interval', 0.1))
        except (TypeError, ValueError):
            return 0.1

    # -- evaluation pipeline ---------------------------------------------
    def evaluate(self) -> RunEvaluationResult:
        auc_rounds = self._compute_auc_per_round()
        ttd_stats = self._compute_ttd_metrics()
        error_rates = self._compute_error_rates()
        bypass_rate = self._compute_bypass_rate()
        stability = self._compute_stability_metrics()
        overhead = self._compute_overhead_metrics()
        pmfa_stats = self._compute_pmfa_stats()
        trust_gap_series = self._compute_trust_gap_series()
        tti_nodes = self.inputs.enhanced_metrics.compute_tti(tau_drop=self.inputs.trust_threshold)
        auroc_thresholds = self._compute_auroc_threshold_metrics(auc_rounds)
        collusion_metrics = self._compute_collusion_amplification(trust_gap_series)
        sybil_metrics = self._compute_sybil_infiltration()
        betrayal_metrics = self._compute_betrayal_detection_delay(tti_nodes)
        comprehensive_metrics = self.inputs.enhanced_metrics.get_comprehensive_metrics()

        summary = self._build_summary(
            auc_rounds=auc_rounds,
            ttd_stats=ttd_stats,
            auroc_thresholds=auroc_thresholds,
            collusion_metrics=collusion_metrics,
            sybil_metrics=sybil_metrics,
            betrayal_metrics=betrayal_metrics,
            error_rates=error_rates,
            bypass_rate=bypass_rate,
            stability=stability,
            overhead=overhead,
            pmfa_stats=pmfa_stats,
            trust_gap_series=trust_gap_series,
            extra_metrics=comprehensive_metrics,
        )

        self._write_summary(summary)
        self._write_per_round_csv("metrics_per_round.csv", auc_rounds)
        self._write_per_round_csv("overhead_per_round.csv", overhead['per_round'])
        self._write_per_round_csv("stability_per_round.csv", stability['per_round'])
        self._write_per_round_csv("trust_gap_per_round.csv", trust_gap_series)
        self._write_per_round_csv("tti_per_node.csv", pd.DataFrame(tti_nodes))
        self._write_per_round_csv("collusion_amplification_per_round.csv", collusion_metrics['per_round'])
        self._write_per_round_csv("betrayal_delay_per_node.csv", betrayal_metrics['per_node'])
        self._write_metrics_raw(auc_rounds, overhead, stability, trust_gap_series)
        self._write_events_jsonl()
        self._write_final_trust()
        figures = self._generate_figures(
            auc_rounds=auc_rounds,
            ttd_stats=ttd_stats,
            overhead=overhead,
            stability=stability,
            pmfa_stats=pmfa_stats,
            trust_gap_series=trust_gap_series,
            tti_nodes=tti_nodes,
            collusion_metrics=collusion_metrics,
            betrayal_metrics=betrayal_metrics,
        )

        return RunEvaluationResult(
            summary_row=summary,
            per_round_metrics=auc_rounds,
            overhead_per_round=overhead['per_round'],
            stability_per_round=stability['per_round'],
            pmfa_stats=pmfa_stats,
            figures=figures,
        )

    # -- metric computations ---------------------------------------------
    def _compute_auc_per_round(self) -> pd.DataFrame:
        if self.trust_df.empty:
            return pd.DataFrame(columns=['round', 'auroc', 'auprc', 'n_malicious', 'n_honest'])

        try:
            rounds = self.inputs.enhanced_metrics.compute_auc_per_round()
        except AttributeError:
            rounds = []

        if rounds:
            df = pd.DataFrame(rounds)
            df = df.rename(columns={'auc_roc': 'auroc', 'auc_pr': 'auprc', 'n_pos': 'n_malicious', 'n_neg': 'n_honest'})
        else:
            rows: List[Dict[str, Any]] = []
            for rnd, group in self.trust_df.groupby('round'):
                labels = group['is_malicious'].astype(int).tolist()
                scores = group['trust_score'].tolist()
                auroc = _safe_auc(labels, scores)
                auprc = compute_auprc(labels, scores)
                rows.append({
                    'round': rnd,
                    'auroc': auroc,
                    'auprc': auprc,
                    'n_malicious': int(group['is_malicious'].sum()),
                    'n_honest': int((~group['is_malicious']).sum()),
                })
            df = pd.DataFrame(rows)

        df = df.sort_values('round')
        for col in ('auroc', 'auprc'):
            if col in df.columns:
                df[col] = df[col].astype(float)
        return df

    def _compute_auroc_threshold_metrics(self, auc_rounds: pd.DataFrame) -> Dict[str, float]:
        if auc_rounds.empty:
            return {
                'round_to_auroc_ge_0p90': float('nan'),
                'auroc_at_round_20': float('nan'),
                'auprc_at_round_20': float('nan'),
            }

        df = auc_rounds[['round', 'auroc', 'auprc']].copy()
        df = df.sort_values('round')
        threshold_round = float('nan')
        threshold_df = df[np.isfinite(df['auroc'])]
        if not threshold_df.empty:
            mask = threshold_df['auroc'] >= 0.90
            if mask.any():
                threshold_round = float(threshold_df.loc[mask, 'round'].iloc[0])

        round20 = df.loc[df['round'] == 20]
        auroc_at_20 = float(round20['auroc'].iloc[0]) if not round20.empty else float('nan')
        auprc_at_20 = float(round20['auprc'].iloc[0]) if not round20.empty else float('nan')
        return {
            'round_to_auroc_ge_0p90': threshold_round,
            'auroc_at_round_20': auroc_at_20,
            'auprc_at_round_20': auprc_at_20,
        }

    def _compute_ttd_metrics(self) -> Dict[str, Any]:
        if self.trust_df.empty:
            return {
                'values': [],
                'median': float('nan'),
                'mean': float('nan'),
                'ci': (float('nan'), float('nan')),
                'median_seconds': float('nan'),
                'mean_seconds': float('nan'),
                'ci_seconds': (float('nan'), float('nan')),
            }

        tau = self.inputs.trust_threshold
        malicious_df = self.trust_df[self.trust_df['is_malicious']]
        ttd_values: List[float] = []
        for node_id, group in malicious_df.groupby('node_id'):
            below_tau = group[group['trust_score'] < tau]
            if below_tau.empty:
                continue
            ttd_values.append(float(below_tau['round'].min()))

        if not ttd_values:
            return {
                'values': [],
                'median': float('nan'),
                'mean': float('nan'),
                'ci': (float('nan'), float('nan')),
                'median_seconds': float('nan'),
                'mean_seconds': float('nan'),
                'ci_seconds': (float('nan'), float('nan')),
            }

        median = float(np.median(ttd_values))
        mean = float(np.mean(ttd_values))
        ci = _bootstrap_ci(ttd_values, func=np.median, ci=0.95, rng=self.rng)
        round_seconds = self._round_duration_seconds()
        values_seconds = [v * round_seconds for v in ttd_values]
        median_seconds = float(np.median(values_seconds))
        mean_seconds = float(np.mean(values_seconds))
        ci_seconds = (ci[0] * round_seconds, ci[1] * round_seconds)
        return {
            'values': ttd_values,
            'median': median,
            'mean': mean,
            'ci': ci,
            'median_seconds': median_seconds,
            'mean_seconds': mean_seconds,
            'ci_seconds': ci_seconds,
        }

    def _compute_betrayal_detection_delay(self, tti_nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        attack_type = (self.inputs.attack_type or '').lower()
        if attack_type != 'betrayal' or not tti_nodes:
            return {
                'per_node': pd.DataFrame(columns=['node_id', 'tti_rounds', 'delay_rounds', 'delay_seconds']),
                'median_rounds': float('nan'),
                'mean_rounds': float('nan'),
                'median_seconds': float('nan'),
                'mean_seconds': float('nan'),
                'never_detected': 0,
            }

        attack_cfg = self.inputs.config.get('attack', {}) if isinstance(self.inputs.config, Mapping) else {}
        betrayal_start = attack_cfg.get('betrayal_iteration')
        try:
            betrayal_start = int(betrayal_start)
        except (TypeError, ValueError):
            return {
                'per_node': pd.DataFrame(columns=['node_id', 'tti_rounds', 'delay_rounds', 'delay_seconds']),
                'median_rounds': float('nan'),
                'mean_rounds': float('nan'),
                'median_seconds': float('nan'),
                'mean_seconds': float('nan'),
                'never_detected': 0,
            }

        round_seconds = self._round_duration_seconds()
        delay_rows: List[Dict[str, Any]] = []
        delays: List[float] = []
        never_detected = 0

        for entry in tti_nodes:
            if int(entry.get('is_malicious', 0)) != 1:
                continue
            tti = entry.get('tti')
            tti_value = self._safe_float(tti)
            tti_round = int(tti_value) if tti_value is not None else -1
            if tti_round < 0:
                delay_rounds = float('nan')
                never_detected += 1
            else:
                delay_rounds = max(0, tti_round - betrayal_start)
                delays.append(delay_rounds)
            delay_rows.append({
                'node_id': entry.get('node_id'),
                'tti_rounds': tti_round,
                'delay_rounds': delay_rounds,
                'delay_seconds': (delay_rounds * round_seconds) if math.isfinite(delay_rounds) else float('nan'),
            })

        per_node_df = pd.DataFrame(delay_rows)
        if not delays:
            return {
                'per_node': per_node_df,
                'median_rounds': float('nan'),
                'mean_rounds': float('nan'),
                'median_seconds': float('nan'),
                'mean_seconds': float('nan'),
                'never_detected': never_detected,
            }

        delays_arr = np.asarray(delays, dtype=float)
        return {
            'per_node': per_node_df,
            'median_rounds': float(np.median(delays_arr)),
            'mean_rounds': float(np.mean(delays_arr)),
            'median_seconds': float(np.median(delays_arr * round_seconds)),
            'mean_seconds': float(np.mean(delays_arr * round_seconds)),
            'never_detected': never_detected,
        }

    def _compute_sybil_infiltration(self) -> Dict[str, float]:
        attack_type = (self.inputs.attack_type or '').lower()
        if self.trust_df.empty or (self.inputs.fraction_sybils or 0.0) <= 0 and attack_type != 'sybil':
            return {
                'sybil_infiltration_rate': float('nan'),
                'sybil_trust_share': float('nan'),
                'n_malicious_final': 0,
                'n_sybil_identities_observed': 0,
            }

        final_round = int(self.trust_df['round'].max())
        final_df = self.trust_df[self.trust_df['round'] == final_round]
        malicious = final_df[final_df['is_malicious']]
        honest = final_df[~final_df['is_malicious']]

        if malicious.empty:
            return {
                'sybil_infiltration_rate': float('nan'),
                'sybil_trust_share': float('nan'),
                'n_malicious_final': 0,
                'n_sybil_identities_observed': 0,
            }

        tau = self.inputs.trust_threshold
        infiltration = float((malicious['trust_score'] >= tau).sum() / len(malicious))
        malicious_trust_sum = float(malicious['trust_score'].sum())
        total_trust = float(malicious_trust_sum + honest['trust_score'].sum())
        if total_trust > 0:
            trust_share = float(malicious_trust_sum / total_trust)
        else:
            trust_share = float('nan')
        identity_count = 0

        if attack_type == 'sybil':
            identity_metrics = self._compute_sybil_identity_infiltration_from_events(
                tau=tau,
                honest_trust_sum=float(honest['trust_score'].sum()),
            )
            if identity_metrics is not None:
                infiltration = identity_metrics.get('sybil_infiltration_rate', infiltration)
                trust_share = identity_metrics.get('sybil_trust_share', trust_share)
                identity_count = int(identity_metrics.get('n_sybil_identities_observed', 0))
        return {
            'sybil_infiltration_rate': infiltration,
            'sybil_trust_share': trust_share,
            'n_malicious_final': int(len(malicious)),
            'n_sybil_identities_observed': identity_count,
        }

    def _compute_sybil_identity_infiltration_from_events(
        self,
        tau: float,
        honest_trust_sum: float,
    ) -> Optional[Dict[str, float]]:
        if not self.inputs.db_path.exists():
            return None
        identity_scores: Dict[str, float] = {}
        try:
            with sqlite3.connect(self.inputs.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT details FROM events WHERE event_type = 'challenge_outcome'"
                ).fetchall()
        except Exception:
            return None

        for row in rows:
            details = row['details']
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except Exception:
                    continue
            if not isinstance(details, dict):
                continue
            identity_id = details.get('sybil_identity_id')
            if not identity_id:
                continue
            trust_value = self._safe_float(details.get('total_trust'))
            if trust_value is None:
                continue
            identity_scores[str(identity_id)] = trust_value

        if not identity_scores:
            return None

        values = np.asarray(list(identity_scores.values()), dtype=float)
        infiltration = float((values >= float(tau)).sum() / len(values))
        sybil_trust = float(values.sum())
        total_trust = float(sybil_trust + max(0.0, honest_trust_sum))
        trust_share = float(sybil_trust / total_trust) if total_trust > 0 else float('nan')
        return {
            'sybil_infiltration_rate': infiltration,
            'sybil_trust_share': trust_share,
            'n_sybil_identities_observed': int(len(identity_scores)),
        }

    def _compute_collusion_amplification(self, trust_gap_series: pd.DataFrame) -> Dict[str, Any]:
        attack_type = (self.inputs.attack_type or '').lower()
        if trust_gap_series is None or trust_gap_series.empty:
            return {
                'per_round': pd.DataFrame(columns=['round', 'amplification_ratio']),
                'final_ratio': float('nan'),
                'mean_ratio': float('nan'),
                'auc_ratio': float('nan'),
            }

        df = trust_gap_series.copy()
        if 'honest_trust' not in df or 'malicious_trust' not in df:
            return {
                'per_round': pd.DataFrame(columns=['round', 'amplification_ratio']),
                'final_ratio': float('nan'),
                'mean_ratio': float('nan'),
                'auc_ratio': float('nan'),
            }

        eps = 1e-9
        df['amplification_ratio'] = df.apply(
            lambda row: float(row['malicious_trust'] / max(row['honest_trust'], eps))
            if math.isfinite(row['malicious_trust']) and math.isfinite(row['honest_trust']) and row['honest_trust'] > 0
            else float('nan'),
            axis=1,
        )

        ratio_valid = df['amplification_ratio'].dropna()
        final_ratio = float(df['amplification_ratio'].iloc[-1]) if not df.empty else float('nan')
        mean_ratio = float(ratio_valid.mean()) if not ratio_valid.empty else float('nan')

        if ratio_valid.empty or len(df) < 2:
            auc_ratio = float('nan')
        else:
            try:
                auc_ratio = float(np.trapezoid(df['amplification_ratio'].astype(float), df['round'].astype(float)))
            except Exception:
                auc_ratio = float('nan')

        if attack_type != 'collusion' and (self.inputs.fraction_colluders or 0.0) <= 0:
            final_ratio = mean_ratio = auc_ratio = float('nan')

        return {
            'per_round': df[['round', 'amplification_ratio']],
            'final_ratio': final_ratio,
            'mean_ratio': mean_ratio,
            'auc_ratio': auc_ratio,
        }

    def _compute_error_rates(self) -> Dict[str, float]:
        if self.trust_df.empty:
            return {
                'fpr_honest': float('nan'),
                'fnr_malicious': float('nan'),
                'tp': float('nan'),
                'fp': float('nan'),
                'tn': float('nan'),
                'fn': float('nan'),
                'accuracy': float('nan'),
                'precision': float('nan'),
                'recall': float('nan'),
                'f1_score': float('nan'),
                'false_positive_rate': float('nan'),
            }

        tau = self.inputs.trust_threshold
        final_round = int(self.trust_df['round'].max())
        final_df = self.trust_df[self.trust_df['round'] == final_round]
        preds = (final_df['trust_score'] < tau)
        labels = final_df['is_malicious'].astype(bool)

        honest_mask = ~labels
        mal_mask = labels
        fpr = float((preds & honest_mask).sum() / honest_mask.sum()) if honest_mask.sum() else float('nan')
        fnr = float((~preds & mal_mask).sum() / mal_mask.sum()) if mal_mask.sum() else float('nan')
        tp = float((preds & mal_mask).sum())
        fp = float((preds & honest_mask).sum())
        tn = float((~preds & honest_mask).sum())
        fn = float((~preds & mal_mask).sum())
        total = tp + fp + tn + fn
        accuracy = float((tp + tn) / total) if total > 0 else float('nan')
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else float('nan')
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else float('nan')
        if math.isfinite(precision) and math.isfinite(recall) and (precision + recall) > 0:
            f1_score = float(2.0 * precision * recall / (precision + recall))
        else:
            f1_score = float('nan')
        false_positive_rate = float(fp / (fp + tn)) if (fp + tn) > 0 else float('nan')
        return {
            'fpr_honest': fpr,
            'fnr_malicious': fnr,
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positive_rate': false_positive_rate,
        }

    def _compute_bypass_rate(self) -> float:
        if self.challenge_df.empty:
            return float('nan')
        malicious = self.challenge_df[self.challenge_df['target_is_malicious']]
        if malicious.empty:
            return float('nan')
        tau = self.inputs.trust_threshold
        bypass = malicious[malicious['trust_after'] >= tau]
        return float(len(bypass) / len(malicious))

    def _compute_overhead_metrics(self) -> Dict[str, Any]:
        if not self.message_df.empty:
            agg = self.message_df.groupby('round').agg(
                msgs=('message_type', 'count'),
                bytes=('payload_bytes', 'sum'),
                latency_ms_mean=('latency_ms', 'mean'),
            ).reset_index()
            return {
                'per_round': agg,
                'msgs_mean': float(agg['msgs'].mean()),
                'bytes_mean': float(agg['bytes'].mean()),
                'latency_mean': float(agg['latency_ms_mean'].mean()),
            }

        return self._estimate_overhead_from_challenges()

    def _compute_stability_metrics(self) -> Dict[str, Any]:
        if self.trust_df.empty:
            return {
                'per_round': pd.DataFrame(columns=['round', 'variance', 'kendall_tau']),
                'variance_mean': float('nan'),
                'kendall_tau_mean': float('nan'),
            }

        variance_rows: List[Dict[str, Any]] = []
        tau_values: List[float] = []

        pivot = self.trust_df.pivot(index='node_id', columns='round', values='trust_score')
        rounds = sorted(pivot.columns)
        prev_vec = None
        for rnd in rounds:
            column = pivot[rnd].to_numpy(dtype=float)
            variance = float(np.nanvar(column, ddof=1)) if np.isfinite(column).sum() > 1 else float('nan')
            kendall = float('nan')
            if prev_vec is not None:
                kendall = _kendall_tau(prev_vec, column)
                if math.isfinite(kendall):
                    tau_values.append(kendall)
            variance_rows.append({'round': rnd, 'variance': variance, 'kendall_tau': kendall})
            prev_vec = column

        df = pd.DataFrame(variance_rows)
        variance_mean = float(df['variance'].mean()) if not df['variance'].empty else float('nan')
        kendall_mean = float(np.nanmean(tau_values)) if tau_values else float('nan')

        return {
            'per_round': df,
            'variance_mean': variance_mean,
            'kendall_tau_mean': kendall_mean,
        }

    def _compute_pmfa_stats(self) -> Dict[str, Any]:
        logs = self.inputs.runtime_snapshot.get('privacy_pmfa_logs', [])
        if not logs:
            return {
                'success_no_verification': float('nan'),
                'success_with_verification': float('nan'),
                'auc_no_verification': float('nan'),
                'auc_with_verification': float('nan'),
            }

        df = pd.DataFrame(logs)
        df['dmpo_enabled'] = df['dmpo_enabled'].astype(bool)
        df['is_challenge'] = df['is_challenge'].astype(int)
        features = df[['delay_ms', 'payload_size']].fillna(0.0).to_numpy(dtype=float)

        results = {}
        for flag, label in [(False, 'no_verification'), (True, 'with_verification')]:
            subset = df[df['dmpo_enabled'] == flag]
            if subset['is_challenge'].nunique() < 2 or subset.empty:
                results[f'success_{label}'] = float('nan')
                results[f'auc_{label}'] = float('nan')
                continue
            try:
                feat = subset[['delay_ms', 'payload_size']].fillna(0.0).to_numpy(dtype=float)
                model = LogisticRegression(max_iter=200, solver='liblinear')
                model.fit(feat, subset['is_challenge'])
                probs = model.predict_proba(feat)[:, 1]
                preds = (probs >= 0.5).astype(int)
                success = float((preds == subset['is_challenge']).mean())
                auc = float(roc_auc_score(subset['is_challenge'], probs))
            except Exception:
                success = float('nan')
                auc = float('nan')
            results[f'success_{label}'] = success
            results[f'auc_{label}'] = auc

        return results

    # -- summary & outputs -----------------------------------------------
    def _build_summary(
        self,
        *,
        auc_rounds: pd.DataFrame,
        ttd_stats: Dict[str, Any],
        auroc_thresholds: Dict[str, float],
        collusion_metrics: Dict[str, Any],
        sybil_metrics: Dict[str, Any],
        betrayal_metrics: Dict[str, Any],
        error_rates: Dict[str, float],
        bypass_rate: float,
        stability: Dict[str, Any],
        overhead: Dict[str, Any],
        pmfa_stats: Dict[str, Any],
        trust_gap_series: pd.DataFrame,
        extra_metrics: Mapping[str, Any],
    ) -> Dict[str, Any]:
        final_auroc = float(auc_rounds['auroc'].iloc[-1]) if not auc_rounds.empty else float('nan')
        mean_auroc = float(auc_rounds['auroc'].mean()) if not auc_rounds.empty else float('nan')
        final_auprc = float(auc_rounds['auprc'].iloc[-1]) if (not auc_rounds.empty and 'auprc' in auc_rounds) else float('nan')
        mean_auprc = float(auc_rounds['auprc'].mean()) if (not auc_rounds.empty and 'auprc' in auc_rounds) else float('nan')
        trust_gap_final = float(trust_gap_series['gap'].iloc[-1]) if not trust_gap_series.empty else float('nan')
        trust_gap_auc = float('nan')
        if not trust_gap_series.empty:
            try:
                finite_gap = (
                    trust_gap_series[['round', 'gap']]
                    .assign(
                        round=lambda x: pd.to_numeric(x['round'], errors='coerce'),
                        gap=lambda x: pd.to_numeric(x['gap'], errors='coerce'),
                    )
                    .dropna()
                    .sort_values('round')
                )
                if len(finite_gap) >= 2:
                    trust_gap_auc = float(
                        np.trapezoid(
                            finite_gap['gap'].to_numpy(dtype=float),
                            finite_gap['round'].to_numpy(dtype=float),
                        )
                    )
                else:
                    trust_gap_auc = compute_trust_gap_auc(trust_gap_series.to_dict('records'))
            except Exception:
                trust_gap_auc = compute_trust_gap_auc(trust_gap_series.to_dict('records'))

        metrics = dict(extra_metrics) if extra_metrics else {}

        def _metric_float(key: str) -> float:
            value = metrics.get(key)
            if value is None:
                return float('nan')
            try:
                return float(value)
            except (TypeError, ValueError):
                return float('nan')

        summary = {
            'scenario': self.inputs.scenario_id,
            'variant': self.inputs.variant_label,
            'run_id': self.inputs.run_id,
            'algo': self.inputs.method,
            'attack': self.inputs.attack_type,
            'topology': self.inputs.topology,
            'N': self.inputs.n_nodes,
            'seed': self.inputs.seed,
            'fraction_colluders': self.inputs.fraction_colluders,
            'fraction_sybils': self.inputs.fraction_sybils,
            'malicious_ratio': self.inputs.malicious_ratio,
            'run_dir': str(self.outputs_dir),
            'trust_threshold': self.inputs.trust_threshold,
            'AUROC_final': final_auroc,
            'AUROC_mean': mean_auroc,
            'AUPRC_final': final_auprc,
            'AUPRC_mean': mean_auprc,
            'TTD_median': ttd_stats['median'],
            'TTD_mean': ttd_stats['mean'],
            'TTD_CI_low': ttd_stats['ci'][0],
            'TTD_CI_high': ttd_stats['ci'][1],
            'TTD_median_seconds': ttd_stats.get('median_seconds'),
            'TTD_mean_seconds': ttd_stats.get('mean_seconds'),
            'TTD_CI_low_seconds': ttd_stats.get('ci_seconds', (float('nan'), float('nan')))[0],
            'TTD_CI_high_seconds': ttd_stats.get('ci_seconds', (float('nan'), float('nan')))[1],
            'FPR_h': error_rates['fpr_honest'],
            'FNR_m': error_rates['fnr_malicious'],
            'bypass_rate': bypass_rate,
            'msgs_per_round_mean': overhead['msgs_mean'],
            'bytes_per_round_mean': overhead['bytes_mean'],
            'latency_per_round_mean': overhead['latency_mean'],
            'stability_variance': stability['variance_mean'],
            'stability_kendall_tau': stability['kendall_tau_mean'],
            'trust_gap_final': trust_gap_final,
            'trust_gap_auc': trust_gap_auc,
            'pmfa_success_rate_no_ver': pmfa_stats.get('success_no_verification'),
            'pmfa_success_rate_with_ver': pmfa_stats.get('success_with_verification'),
            'pmfa_auc_no_ver': pmfa_stats.get('auc_no_verification'),
            'pmfa_auc_with_ver': pmfa_stats.get('auc_with_verification'),
            'db_path': str(self.inputs.db_path),
            'fqr': _metric_float('fqr'),
            'fnrq': _metric_float('fnrq'),
            'cpu_time_ms': _metric_float('cpu_time_ms'),
            'mem_peak_mb': _metric_float('mem_peak_mb'),
            'alpha_star': _metric_float('alpha_star'),
            'round_to_auroc_ge_0p90': auroc_thresholds.get('round_to_auroc_ge_0p90', float('nan')),
            'auroc_at_round_20': auroc_thresholds.get('auroc_at_round_20', float('nan')),
            'auprc_at_round_20': auroc_thresholds.get('auprc_at_round_20', float('nan')),
            'collusion_amplification_final': collusion_metrics.get('final_ratio'),
            'collusion_amplification_mean': collusion_metrics.get('mean_ratio'),
            'collusion_amplification_auc': collusion_metrics.get('auc_ratio'),
            'sybil_infiltration_rate': sybil_metrics.get('sybil_infiltration_rate'),
            'sybil_trust_share': sybil_metrics.get('sybil_trust_share'),
            'betrayal_delay_median_rounds': betrayal_metrics.get('median_rounds'),
            'betrayal_delay_mean_rounds': betrayal_metrics.get('mean_rounds'),
            'betrayal_delay_median_seconds': betrayal_metrics.get('median_seconds'),
            'betrayal_delay_mean_seconds': betrayal_metrics.get('mean_seconds'),
            'betrayal_never_detected': betrayal_metrics.get('never_detected'),
        }

        def _finite(value: Any) -> bool:
            try:
                val = float(value)
            except (TypeError, ValueError):
                return False
            return not math.isnan(val)

        summary.update({
            # Keep classification metrics threshold-consistent with FPR_h/FNR_m:
            # all are computed from final-round trust snapshot at tau.
            'accuracy': error_rates.get('accuracy'),
            'precision': error_rates.get('precision'),
            'recall': error_rates.get('recall'),
            'f1_score': error_rates.get('f1_score'),
            'false_positive_rate': error_rates.get('false_positive_rate'),
            'time_to_demote': _metric_float('time_to_demote'),
            'trust_degradation': _metric_float('trust_degradation'),
            'misalignment': _metric_float('misalignment'),
            'undetected_malicious': _metric_float('undetected_malicious'),
            'tti_mean': _metric_float('tti_mean'),
            'tti_q1': _metric_float('tti_q1'),
            'tti_q3': _metric_float('tti_q3'),
            'tti_p95': _metric_float('tti_p95'),
        })

        if not _finite(summary['latency_per_round_mean']):
            summary['latency_per_round_mean'] = _metric_float('latency_ms_mean')
        if not _finite(summary['msgs_per_round_mean']):
            summary['msgs_per_round_mean'] = _metric_float('msgs_per_round_mean')
        if not _finite(summary['bytes_per_round_mean']):
            summary['bytes_per_round_mean'] = _metric_float('bytes_mean')

        asr_metric = _metric_float('asr')
        summary['asr'] = asr_metric if _finite(asr_metric) else summary['bypass_rate']

        return summary

    def _estimate_overhead_from_challenges(self) -> Dict[str, Any]:
        if self.challenge_df.empty:
            per_round = pd.DataFrame(columns=['round', 'msgs', 'bytes', 'latency_ms_mean'])
            return {
                'per_round': per_round,
                'msgs_mean': float('nan'),
                'bytes_mean': float('nan'),
                'latency_mean': float('nan'),
            }

        per_round_rows: List[Dict[str, float]] = []
        default_latency_ms = float(self.inputs.config.get('simulation', {}).get('update_interval', 0.1) * 1000.0)
        collab_latency = self.inputs.runtime_snapshot.get('collab_latency', {}) or {}

        for _, row in self.challenge_df.iterrows():
            round_idx = int(row.get('round', row.get('iteration', 0)))
            exchange = self._challenge_exchange_stats(row, default_latency_ms, collab_latency.get(round_idx))
            per_round_rows.append({
                'round': float(round_idx),
                'msgs': exchange['messages'],
                'bytes': exchange['bytes'],
                'latency_ms_mean': exchange['latency_ms'],
            })

        per_round = pd.DataFrame(per_round_rows)
        if per_round.empty:
            per_round = pd.DataFrame(columns=['round', 'msgs', 'bytes', 'latency_ms_mean'])
        else:
            per_round = per_round.groupby('round', as_index=False).agg({
                'msgs': 'sum',
                'bytes': 'sum',
                'latency_ms_mean': 'mean',
            })

        return {
            'per_round': per_round,
            'msgs_mean': float(per_round['msgs'].mean()) if not per_round.empty else float('nan'),
            'bytes_mean': float(per_round['bytes'].mean()) if not per_round.empty else float('nan'),
            'latency_mean': float(per_round['latency_ms_mean'].mean()) if not per_round.empty else float('nan'),
        }

    def _challenge_exchange_stats(
        self,
        row: pd.Series,
        default_latency_ms: float,
        round_latency_samples: Optional[Sequence[float]],
    ) -> Dict[str, float]:
        base_payload: Dict[str, Any] = {
            'source': int(row.get('source_node', -1)),
            'target': int(row.get('target_node', -1)),
            'round': int(row.get('round', row.get('iteration', 0))),
            'trust_before': self._safe_float(row.get('trust_before')),
            'trust_after': self._safe_float(row.get('trust_after')),
            'threshold': self._safe_float(row.get('detection_threshold')),
            'target_is_malicious': bool(row.get('target_is_malicious', False)),
        }

        payload_lens: List[float] = []

        def _payload_size(message: Dict[str, Any]) -> float:
            sanitized = {k: self._sanitize_payload_value(v) for k, v in message.items()}
            try:
                return float(len(json.dumps(sanitized, separators=(',', ':')).encode('utf-8')))
            except Exception:
                return float(len(str(sanitized).encode('utf-8')))

        stages = (
            ('basic', self._safe_float(row.get('basic'))),
            ('advanced', self._safe_float(row.get('advanced'))),
            ('final', self._safe_float(row.get('final'))),
        )

        for stage, score in stages:
            if score is None:
                continue
            request: Dict[str, Any] = dict(base_payload)
            request.update({'stage': stage, 'direction': 'request', 'score': score})
            if stage == 'advanced':
                request.update({
                    'reputation': self._safe_float(row.get('reputation')),
                    'contribution': self._safe_float(row.get('contribution')),
                    'penalty': self._safe_float(row.get('penalty')),
                })
            if stage == 'final':
                request.update({
                    'auth_status': self._safe_float(row.get('auth')),
                    'biometric': self._safe_float(row.get('biometric_score', row.get('final'))),
                })

            response: Dict[str, Any] = dict(base_payload)
            response.update({'stage': stage, 'direction': 'response', 'score': score})

            payload_lens.append(_payload_size(request))
            payload_lens.append(_payload_size(response))

        messages = len(payload_lens)
        bytes_total = float(sum(payload_lens)) if payload_lens else 0.0

        if round_latency_samples:
            latency_ms = float(np.mean(round_latency_samples))
        else:
            latency_ms = default_latency_ms

        return {
            'messages': float(messages),
            'bytes': bytes_total,
            'latency_ms': latency_ms,
        }

    @staticmethod
    def _safe_float(value: Any) -> Optional[float]:
        try:
            val = float(value)
            if math.isnan(val) or math.isinf(val):
                return None
            return val
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _sanitize_payload_value(value: Any) -> Any:
        if isinstance(value, (int, str, bool)) or value is None:
            return value
        try:
            val = float(value)
            if math.isnan(val) or math.isinf(val):
                return None
            return round(val, 6)
        except (TypeError, ValueError):
            return str(value)

    def _compute_trust_gap_series(self) -> pd.DataFrame:
        if self.trust_df.empty:
            return pd.DataFrame(columns=['round', 'gap'])
        grp = self.trust_df.groupby(['round', 'is_malicious'])['trust_score'].mean().unstack(fill_value=np.nan)
        grp = grp.reset_index().rename(columns={False: 'honest_trust', True: 'malicious_trust'})

        # One-class scenarios (e.g., benign smoke) may miss one side.
        if 'honest_trust' not in grp.columns:
            grp['honest_trust'] = np.nan
        if 'malicious_trust' not in grp.columns:
            grp['malicious_trust'] = np.nan

        grp['gap'] = grp['honest_trust'] - grp['malicious_trust']
        return grp[['round', 'honest_trust', 'malicious_trust', 'gap']]

    def _write_summary(self, summary: Dict[str, Any]) -> None:
        df = pd.DataFrame([summary])
        df.to_csv(self.outputs_dir / 'summary.csv', index=False)
        try:
            (self.outputs_dir / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        except Exception:
            self.logger.debug("Failed to write summary.json", exc_info=True)

    def _write_per_round_csv(self, filename: str, df: pd.DataFrame) -> None:
        if df.empty:
            Path(self.outputs_dir / filename).write_text("", encoding='utf-8')
        else:
            df.to_csv(self.outputs_dir / filename, index=False)

    def _write_metrics_raw(
        self,
        auc_rounds: pd.DataFrame,
        overhead: Dict[str, Any],
        stability: Dict[str, Any],
        trust_gap_series: pd.DataFrame,
    ) -> None:
        df = auc_rounds.copy() if not auc_rounds.empty else pd.DataFrame()

        if isinstance(overhead.get('per_round'), pd.DataFrame) and not overhead['per_round'].empty:
            df = df.merge(overhead['per_round'], on='round', how='outer') if not df.empty else overhead['per_round']
        if isinstance(stability.get('per_round'), pd.DataFrame) and not stability['per_round'].empty:
            df = df.merge(stability['per_round'], on='round', how='outer') if not df.empty else stability['per_round']
        if trust_gap_series is not None and not trust_gap_series.empty:
            df = df.merge(trust_gap_series, on='round', how='outer') if not df.empty else trust_gap_series

        metrics_csv = self.outputs_dir / "metrics_raw.csv"
        if df.empty:
            metrics_csv.write_text("", encoding="utf-8")
        else:
            df.to_csv(metrics_csv, index=False)
            try:
                df.to_parquet(self.outputs_dir / "metrics_raw.parquet", index=False)
            except Exception:
                self.logger.debug("Parquet export skipped (dependency missing).")

    def _write_events_jsonl(self) -> None:
        events_path = self.outputs_dir / 'events.jsonl'
        with sqlite3.connect(self.inputs.db_path) as conn, events_path.open('w', encoding='utf-8') as handle:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT timestamp, iteration, node_id, related_node_id, event_type, details FROM events ORDER BY iteration, timestamp"
            ).fetchall()
            for row in rows:
                record = dict(row)
                details = record.get('details')
                if isinstance(details, str):
                    try:
                        record['details'] = json.loads(details)
                    except Exception:
                        record['details'] = details
                handle.write(json.dumps(record) + "\n")

    def _write_final_trust(self) -> None:
        if self.trust_df.empty:
            Path(self.outputs_dir / 'final_trust.csv').write_text("", encoding='utf-8')
            return
        final_round = int(self.trust_df['round'].max())
        final_df = self.trust_df[self.trust_df['round'] == final_round][['node_id', 'trust_score', 'is_malicious']]
        final_df.to_csv(self.outputs_dir / 'final_trust.csv', index=False)

    def _save_figure(self, fig: plt.Figure, filename: str) -> Path:
        path = self.fig_dir / filename
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
        return path

    # -- plotting --------------------------------------------------------
    def _generate_figures(
        self,
        *,
        auc_rounds: pd.DataFrame,
        ttd_stats: Dict[str, Any],
        overhead: Dict[str, Any],
        stability: Dict[str, Any],
        pmfa_stats: Dict[str, Any],
        trust_gap_series: pd.DataFrame,
        tti_nodes: List[Dict[str, Any]],
        collusion_metrics: Dict[str, Any],
        betrayal_metrics: Dict[str, Any],
    ) -> Dict[str, Path]:
        figures: Dict[str, Path] = {}

        if not auc_rounds.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(auc_rounds['round'], auc_rounds['auroc'], label='AUROC', marker='o', linewidth=1.5)
            if 'auprc' in auc_rounds and auc_rounds['auprc'].notna().any():
                ax.plot(auc_rounds['round'], auc_rounds['auprc'], label='AUPRC', marker='s', linewidth=1.5, linestyle='--')
            ax.set_xlabel('Round')
            ax.set_ylabel('Area')
            ax.set_title('AUC vs Time')
            ax.grid(True, alpha=0.3)
            if ax.get_legend_handles_labels()[0]:
                ax.legend(loc='lower right')
            fig.tight_layout()
            path = self._save_figure(fig, 'auroc_vs_time.png')
            figures['auroc_vs_time'] = path

        if ttd_stats['values']:
            sorted_vals = np.sort(ttd_stats['values'])
            cdf = np.arange(1, len(sorted_vals) + 1) / len(sorted_vals)
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.step(sorted_vals, cdf, where='post')
            ax.set_xlabel('Rounds to Detection (TTD)')
            ax.set_ylabel('CDF')
            ax.set_title('TTD CDF')
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            path = self._save_figure(fig, 'ttd_cdf.png')
            figures['ttd_cdf'] = path

        if tti_nodes:
            df_tti = pd.DataFrame(tti_nodes)
            detected = df_tti[df_tti['tti'] >= 0]
            fig, ax = plt.subplots(figsize=(5, 4))
            if detected.empty:
                ax.text(0.5, 0.5, 'No malicious node detected', ha='center', va='center')
            else:
                ax.bar(detected['node_id'].astype(int), detected['tti'].astype(int))
                ax.set_xlabel('Node ID')
                ax.set_ylabel('Detection Round')
                ax.set_title('TTD per Malicious Node')
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            path = self._save_figure(fig, 'tti_per_node.png')
            figures['tti_per_node'] = path

        overhead_df = overhead['per_round']
        if not overhead_df.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(overhead_df['round'], overhead_df['msgs'], label='Messages', linewidth=1.5)
            ax.set_xlabel('Round')
            ax.set_ylabel('Messages per round')
            ax_twin = ax.twinx()
            ax_twin.plot(overhead_df['round'], overhead_df['bytes'], color='orange', label='Bytes', linewidth=1.5)
            ax.set_title('Collaboration Overhead')
            ax.grid(True, alpha=0.3)
            lines, labels = ax.get_legend_handles_labels()
            lines2, labels2 = ax_twin.get_legend_handles_labels()
            ax.legend(lines + lines2, labels + labels2, loc='upper right')
            fig.tight_layout()
            path = self._save_figure(fig, 'overhead_per_round.png')
            figures['overhead'] = path

        stability_df = stability['per_round']
        if not stability_df.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(stability_df['round'], stability_df['kendall_tau'], marker='o', linewidth=1.5)
            ax.set_ylim(-1.05, 1.05)
            ax.set_xlabel('Round')
            ax.set_ylabel('Kendall τ (t, t-1)')
            ax.set_title('Stability (Rank Correlation)')
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            path = self._save_figure(fig, 'stability_kendall.png')
            figures['stability'] = path

        if trust_gap_series is not None and not trust_gap_series.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(trust_gap_series['round'], trust_gap_series['honest_trust'], label='Honest')
            ax.plot(trust_gap_series['round'], trust_gap_series['malicious_trust'], label='Malicious')
            ax.set_xlabel('Round')
            ax.set_ylabel('Trust score')
            ax.set_ylim(0, 1)
            ax.grid(True, alpha=0.3)
            ax2 = ax.twinx()
            ax2.plot(trust_gap_series['round'], trust_gap_series['gap'], color='grey', linestyle='--', label='Gap')
            ax2.set_ylabel('Gap')
            fig.tight_layout()
            path = self._save_figure(fig, 'trust_gap.png')
            figures['trust_gap'] = path

        if not math.isnan(pmfa_stats.get('success_no_verification', float('nan'))):
            fig, ax = plt.subplots(figsize=(5, 4))
            categories = ['No Verification', 'With Verification']
            success_rates = [
                pmfa_stats.get('success_no_verification', np.nan),
                pmfa_stats.get('success_with_verification', np.nan),
            ]
            ax.bar(categories, success_rates, color=['tab:red', 'tab:green'])
            ax.set_ylim(0, 1)
            ax.set_ylabel('Attack success rate')
            ax.set_title('PMFA Success')
            fig.tight_layout()
            path = self._save_figure(fig, 'pmfa_success.png')
            figures['pmfa_success'] = path

        col_df = collusion_metrics.get('per_round')
        if isinstance(col_df, pd.DataFrame) and not col_df.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(col_df['round'], col_df['amplification_ratio'], marker='o', linewidth=1.5)
            ax.set_xlabel('Round')
            ax.set_ylabel('Amplification Ratio (malicious / honest)')
            ax.set_title('Collusion Amplification Index')
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            path = self._save_figure(fig, 'collusion_amplification.png')
            figures['collusion_amplification'] = path

        betrayal_df = betrayal_metrics.get('per_node')
        if isinstance(betrayal_df, pd.DataFrame) and not betrayal_df.empty:
            detected_df = betrayal_df[np.isfinite(betrayal_df['delay_seconds'])]
            fig, ax = plt.subplots(figsize=(6, 4))
            if detected_df.empty:
                ax.text(0.5, 0.5, 'No betrayal detections', ha='center', va='center')
                ax.set_axis_off()
            else:
                ax.bar(detected_df['node_id'].astype(str), detected_df['delay_seconds'])
                ax.set_xlabel('Node ID')
                ax.set_ylabel('Delay (seconds)')
                ax.set_title('Betrayal Detection Delay')
                ax.grid(True, axis='y', alpha=0.3)
            fig.tight_layout()
            path = self._save_figure(fig, 'betrayal_detection_delay.png')
            figures['betrayal_delay'] = path

        return figures


__all__ = [
    'RunEvaluator',
    'RunEvaluationInputs',
    'RunEvaluationResult',
]
