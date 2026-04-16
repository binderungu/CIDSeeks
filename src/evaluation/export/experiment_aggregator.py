"""Scenario-level aggregation and statistical testing for CIDSeeks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats


METRIC_COLUMNS: List[str] = [
    'AUROC_final',
    'AUROC_mean',
    'AUPRC_final',
    'AUPRC_mean',
    'round_to_auroc_ge_0p90',
    'auroc_at_round_20',
    'auprc_at_round_20',
    'TTD_median',
    'TTD_mean',
    'TTD_CI_low',
    'TTD_CI_high',
    'TTD_median_seconds',
    'TTD_mean_seconds',
    'TTD_CI_low_seconds',
    'TTD_CI_high_seconds',
    'FPR_h',
    'FNR_m',
    'bypass_rate',
    'msgs_per_round_mean',
    'bytes_per_round_mean',
    'latency_per_round_mean',
    'stability_kendall_tau',
    'pmfa_success_rate_no_ver',
    'pmfa_success_rate_with_ver',
    'pmfa_success_rate_baseline_no_privacy',
    'pmfa_success_rate_legacy_dmpo',
    'pmfa_success_rate_dmpo_x',
    'pmfa_auc_baseline_no_privacy',
    'pmfa_auc_legacy_dmpo',
    'pmfa_auc_dmpo_x',
    'pmfa_open_adv_baseline_no_privacy',
    'pmfa_open_adv_legacy_dmpo',
    'pmfa_open_adv_dmpo_x',
    'pmfa_drift_auc_baseline_no_privacy',
    'pmfa_drift_auc_legacy_dmpo',
    'pmfa_drift_auc_dmpo_x',
    'trust_gap_final',
    'trust_gap_auc',
    'fibd_mean',
    'split_fail_mean',
    'coalcorr_mean',
    'apmfa_penalty_mean',
    'apmfa_penalty_mean_malicious',
    'final_split_fail_penalty_mean',
    'attribution_signal_count_mean',
    'collusion_amplification_final',
    'collusion_amplification_mean',
    'collusion_amplification_auc',
    'sybil_infiltration_rate',
    'sybil_trust_share',
    'betrayal_delay_median_rounds',
    'betrayal_delay_mean_rounds',
    'betrayal_delay_median_seconds',
    'betrayal_delay_mean_seconds',
    'betrayal_never_detected',
    'fqr',
    'fnrq',
    'cpu_time_ms',
    'mem_peak_mb',
    'alpha_star',
]


def _bootstrap_ci(
    values: Sequence[float],
    func=np.mean,
    ci: float = 0.95,
    resamples: int = 10000,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[float, float]:
    arr = np.asarray([float(v) for v in values if np.isfinite(v)], dtype=float)
    if arr.size == 0:
        return float('nan'), float('nan')
    if arr.size == 1:
        val = float(func(arr))
        return val, val
    rng = rng or np.random.default_rng(0)
    stats_samples = []
    for _ in range(max(1, resamples)):
        try:
            resample = rng.choice(arr, size=arr.size, replace=True)
            stats_samples.append(float(func(resample)))
        except Exception:
            continue
    if not stats_samples:
        return float('nan'), float('nan')
    alpha = (1.0 - ci) / 2.0
    return (
        float(np.percentile(stats_samples, alpha * 100.0)),
        float(np.percentile(stats_samples, (1.0 - alpha) * 100.0)),
    )


def cliffs_delta(x: Sequence[float], y: Sequence[float]) -> float:
    x = [float(v) for v in x if np.isfinite(v)]
    y = [float(v) for v in y if np.isfinite(v)]
    if not x or not y:
        return float('nan')
    greater = 0
    less = 0
    for xi in x:
        for yj in y:
            if xi > yj:
                greater += 1
            elif xi < yj:
                less += 1
    n = len(x) * len(y)
    return (greater - less) / n if n else float('nan')


def benjamini_hochberg(p_values: Dict[Tuple[str, str, str], float]) -> Dict[Tuple[str, str, str], float]:
    if not p_values:
        return {}
    adjusted: Dict[Tuple[str, str, str], float] = {}
    finite_items: List[Tuple[Tuple[str, str, str], float]] = []
    for key, value in p_values.items():
        try:
            p_val = float(value)
        except (TypeError, ValueError):
            adjusted[key] = float("nan")
            continue
        if not np.isfinite(p_val):
            adjusted[key] = float("nan")
            continue
        finite_items.append((key, min(max(p_val, 0.0), 1.0)))

    if not finite_items:
        return adjusted

    finite_items.sort(key=lambda kv: kv[1])
    m = len(finite_items)
    ranked_adjusted: List[float] = [float("nan")] * m
    prev = 1.0
    # BH requires a reverse cumulative minimum on p_i * m / rank.
    for idx in range(m - 1, -1, -1):
        key, p_val = finite_items[idx]
        rank = idx + 1
        bh = min(p_val * m / rank, 1.0)
        prev = min(prev, bh)
        ranked_adjusted[idx] = prev

    for (key, _), p_adj in zip(finite_items, ranked_adjusted):
        adjusted[key] = p_adj
    return adjusted


# ---- DeLong implementation -------------------------------------------------


def _compute_midrank(x: np.ndarray) -> np.ndarray:
    J = np.argsort(x)
    Z = x[J]
    N = len(x)
    T = np.zeros(N, dtype=float)
    i = 0
    while i < N:
        j = i
        while j < N and Z[j] == Z[i]:
            j += 1
        T[i:j] = 0.5 * (i + j - 1)
        i = j
    T2 = np.empty(N, dtype=float)
    T2[J] = T + 1
    return T2


def _delong_covariance(ground_truth: np.ndarray, predictions: np.ndarray) -> Tuple[np.ndarray, float, np.ndarray]:
    positive_idx = ground_truth == 1
    negative_idx = ground_truth == 0
    m = positive_idx.sum()
    n = negative_idx.sum()
    if m == 0 or n == 0:
        raise ValueError('Need both positive and negative samples for DeLong test')

    positive_predictions = predictions[:, positive_idx]
    negative_predictions = predictions[:, negative_idx]
    k = predictions.shape[0]

    tx = np.zeros((k, m))
    ty = np.zeros((k, n))
    tz = np.zeros((k, m + n))

    for r in range(k):
        tx[r, :] = _compute_midrank(positive_predictions[r, :])
        ty[r, :] = _compute_midrank(negative_predictions[r, :])
        tz[r, :] = _compute_midrank(predictions[r, :])

    aucs = tz[:, positive_idx].sum(axis=1) / (m * n) - (m + 1.0) / (2.0 * n)
    v01 = (tz[:, positive_idx] - tx) / n
    v10 = 1.0 - (tz[:, negative_idx] - ty) / m
    sx = np.cov(v01)
    sy = np.cov(v10)
    return sx + sy, aucs[0], aucs


def delong_roc_test(ground_truth: np.ndarray, predictions_one: np.ndarray, predictions_two: np.ndarray) -> float:
    if ground_truth.ndim != 1:
        raise ValueError('ground_truth must be 1-D array')
    if predictions_one.ndim != 1 or predictions_two.ndim != 1:
        raise ValueError('predictions must be 1-D arrays')
    preds = np.vstack((predictions_one, predictions_two))
    cov_matrix, auc1, aucs = _delong_covariance(ground_truth, preds)
    auc2 = aucs[1]
    diff = auc1 - auc2
    var = cov_matrix[0, 0] + cov_matrix[1, 1] - 2 * cov_matrix[0, 1]
    if var <= 0:
        return float('nan')
    z = diff / np.sqrt(var)
    p = stats.norm.sf(abs(z)) * 2
    return float(p)


@dataclass
class AggregatedMetric:
    scenario: str
    variant: str
    metric: str
    method: str
    mean: float
    std: float
    ci_low: float
    ci_high: float
    ci_width: float
    ci_method: str
    n_seeds: int
    power_warning: bool


class ExperimentAggregator:
    """Aggregates per-run summaries and emits scenario-level statistics."""

    def __init__(
        self,
        output_dir: Union[str, Path],
        bootstrap_samples: int = 10000,
        confidence: float = 0.95,
        alpha_thresholds: Optional[Dict[str, float]] = None,
        seed: Optional[int] = None,
        gate_config: Optional[Dict[str, Any]] = None,
        batch_id: Optional[str] = None,
        aggregation_scope: str = "current_batch_records_only",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.bootstrap_samples = bootstrap_samples
        self.confidence = confidence
        self.alpha_thresholds = alpha_thresholds or {}
        try:
            resolved_seed = 0 if seed is None else int(seed)
        except (TypeError, ValueError):
            resolved_seed = 0
        self.rng = np.random.default_rng(resolved_seed)
        self.ci_method = "bootstrap"
        self.gate_config = self._resolve_gate_config(gate_config)
        self.batch_id = str(batch_id or "adhoc_batch")
        self.aggregation_scope = str(aggregation_scope or "current_batch_records_only")

        self.records: List[Dict[str, Any]] = []
        self.run_log_path = self.output_dir / 'run_log.jsonl'
        self.batch_manifest_path = self.output_dir / 'batch_manifest.json'

    def add_run(self, summary_row: Dict[str, Any], run_dir: Union[str, Path]) -> None:
        row = dict(summary_row)
        row['run_dir'] = str(run_dir)
        self.records.append(row)
        with self.run_log_path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(row) + '\n')

    def finalize(self) -> Dict[str, pd.DataFrame]:
        if not self.records:
            return {}

        df = pd.DataFrame(self.records)
        df.to_csv(self.output_dir / 'experiments.csv', index=False)

        aggregate_df = self._build_aggregate_table(df)
        aggregate_df.to_csv(self.output_dir / 'aggregate.csv', index=False)
        aggregate_df.to_csv(self.output_dir / 'aggregate_summary.csv', index=False)

        stats_df = self._build_statistics_table(df)
        stats_df.to_csv(self.output_dir / 'stats.csv', index=False)
        self._write_batch_manifest(df)
        stats_gate = self._build_stats_gate(aggregate_df)
        (self.output_dir / "stats_gate.json").write_text(
            json.dumps(stats_gate, indent=2),
            encoding="utf-8",
        )

        # Ensure suite-level plot directory exists (plots generated by orchestrator)
        (self.output_dir / 'aggregate_plots').mkdir(parents=True, exist_ok=True)

        readme = self.output_dir / 'README.md'
        if not readme.exists():
            readme.write_text(
                "Suite outputs for CIDSeeks Evaluation-2.\n\n"
                "- `experiments.csv`: per-run summary rows for the current aggregation batch\n"
                "- `aggregate_summary.csv`: aggregated metrics\n"
                "- `batch_manifest.json`: provenance for the aggregation batch\n"
                "- `stats_gate.json`: reproducibility/statistics gate result\n"
                "- `aggregate_plots/`: suite-level figures\n",
                encoding="utf-8",
            )

        return {'experiments': df, 'aggregate': aggregate_df, 'stats': stats_df}

    # ------------------------------------------------------------------
    def _resolve_gate_config(self, gate_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        suite_name = self.output_dir.name
        defaults: Dict[str, Any] = {
            "min_seeds": 1 if suite_name in {"smoke", "acceptance"} else 10,
            "required_metrics": ["AUROC_final"],
            "max_ci_width": {},
            "enforce": True,
        }
        merged: Dict[str, Any] = dict(defaults)
        if isinstance(gate_config, dict):
            merged.update(gate_config)
        max_ci_width = merged.get("max_ci_width")
        if not isinstance(max_ci_width, dict):
            merged["max_ci_width"] = {}
        required_metrics = merged.get("required_metrics")
        if not isinstance(required_metrics, list) or not required_metrics:
            merged["required_metrics"] = ["AUROC_final"]
        min_seeds_raw = merged.get("min_seeds", defaults["min_seeds"])
        min_seeds_value = int(defaults["min_seeds"])
        if isinstance(min_seeds_raw, bool):
            min_seeds_value = int(min_seeds_raw)
        elif isinstance(min_seeds_raw, (int, float, str)):
            try:
                min_seeds_value = int(min_seeds_raw)
            except (TypeError, ValueError):
                min_seeds_value = int(defaults["min_seeds"])
        merged["min_seeds"] = min_seeds_value
        merged["enforce"] = bool(merged.get("enforce", True))
        return merged

    def _write_batch_manifest(self, df: pd.DataFrame) -> None:
        run_ids = []
        if "run_id" in df.columns:
            run_ids = [str(value) for value in df["run_id"].dropna().tolist()]
        experiment_ids = []
        if "run_id" in df.columns:
            experiment_ids = sorted({str(value).split("__", 1)[0] for value in df["run_id"].dropna().tolist()})
        seeds = []
        if "seed" in df.columns:
            seeds = sorted({int(value) for value in pd.to_numeric(df["seed"], errors="coerce").dropna().astype(int).tolist()})

        payload = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "suite": self.output_dir.name,
            "output_dir": str(self.output_dir),
            "batch_id": self.batch_id,
            "aggregation_scope": self.aggregation_scope,
            "n_rows": int(len(df)),
            "n_unique_runs": int(len(set(run_ids))),
            "n_unique_experiments": int(len(experiment_ids)),
            "n_unique_seeds": int(len(seeds)),
            "run_ids": run_ids,
            "experiment_ids": experiment_ids,
            "seeds": seeds,
        }
        self.batch_manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _build_aggregate_table(self, df: pd.DataFrame) -> pd.DataFrame:
        rows: List[AggregatedMetric] = []
        min_seed_gate = int(self.gate_config.get("min_seeds", 1))
        for (scenario, variant, method), group in df.groupby(['scenario', 'variant', 'algo']):
            n_seeds = int(group['seed'].nunique()) if 'seed' in group.columns else int(len(group))
            for metric in METRIC_COLUMNS:
                if metric not in group.columns:
                    rows.append(
                        AggregatedMetric(
                            scenario,
                            variant,
                            metric,
                            method,
                            float('nan'),
                            float('nan'),
                            float('nan'),
                            float('nan'),
                            float('nan'),
                            self.ci_method,
                            n_seeds,
                            n_seeds < min_seed_gate,
                        )
                    )
                    continue
                values = pd.to_numeric(group[metric], errors='coerce').dropna()
                if values.empty:
                    rows.append(
                        AggregatedMetric(
                            scenario,
                            variant,
                            metric,
                            method,
                            float('nan'),
                            float('nan'),
                            float('nan'),
                            float('nan'),
                            float('nan'),
                            self.ci_method,
                            n_seeds,
                            n_seeds < min_seed_gate,
                        )
                    )
                    continue
                mean = float(values.mean())
                std = float(values.std(ddof=1)) if values.size > 1 else 0.0
                ci_low, ci_high = _bootstrap_ci(values, ci=self.confidence, resamples=self.bootstrap_samples, rng=self.rng)
                ci_width = float(ci_high - ci_low) if np.isfinite(ci_low) and np.isfinite(ci_high) else float('nan')
                rows.append(
                    AggregatedMetric(
                        scenario,
                        variant,
                        metric,
                        method,
                        mean,
                        std,
                        ci_low,
                        ci_high,
                        ci_width,
                        self.ci_method,
                        n_seeds,
                        n_seeds < min_seed_gate,
                    )
                )

        aggregate_df = pd.DataFrame([row.__dict__ for row in rows])
        cost_rows = self._compute_cost_effectiveness(df, aggregate_df)
        if cost_rows:
            aggregate_df = pd.concat([aggregate_df, pd.DataFrame(cost_rows)], ignore_index=True)
        return aggregate_df

    def _compute_cost_effectiveness(self, raw_df: pd.DataFrame, aggregate_df: pd.DataFrame) -> List[Dict[str, Any]]:
        cost_rows: List[Dict[str, Any]] = []
        for (scenario, variant), group in raw_df.groupby(['scenario', 'variant']):
            methods = sorted(group['algo'].unique())
            if len(methods) < 2:
                continue
            reference_method = 'ours' if 'ours' in methods else methods[0]

            agg_slice = aggregate_df[(aggregate_df['scenario'] == scenario) & (aggregate_df['variant'] == variant)]
            def metric_mean(method: str, metric: str) -> float:
                row = agg_slice[(agg_slice['method'] == method) & (agg_slice['metric'] == metric)]
                return float(row['mean'].iloc[0]) if not row.empty else float('nan')

            reference_msgs = metric_mean(reference_method, 'msgs_per_round_mean')
            reference_auroc = metric_mean(reference_method, 'AUROC_final')
            reference_ttd = metric_mean(reference_method, 'TTD_median')

            for method in methods:
                msg_mean = metric_mean(method, 'msgs_per_round_mean')
                auroc_mean = metric_mean(method, 'AUROC_final')
                ttd_mean = metric_mean(method, 'TTD_median')
                if not np.isfinite(msg_mean):
                    continue

                auroc_gain = auroc_mean - reference_auroc
                cost_auroc = msg_mean / auroc_gain if np.isfinite(auroc_gain) and auroc_gain > 0 else float('nan')

                ttd_drop = reference_ttd - ttd_mean
                cost_ttd = msg_mean / ttd_drop if np.isfinite(ttd_drop) and ttd_drop > 0 else float('nan')

                cost_rows.append({
                    'scenario': scenario,
                    'variant': variant,
                    'metric': 'cost_per_auroc_gain',
                    'method': method,
                    'mean': cost_auroc,
                    'std': float('nan'),
                    'ci_low': float('nan'),
                    'ci_high': float('nan'),
                    'ci_width': float('nan'),
                    'ci_method': self.ci_method,
                    'n_seeds': int(group['seed'].nunique()) if 'seed' in group.columns else int(len(group)),
                    'power_warning': False,
                })
                cost_rows.append({
                    'scenario': scenario,
                    'variant': variant,
                    'metric': 'cost_per_ttd_drop',
                    'method': method,
                    'mean': cost_ttd,
                    'std': float('nan'),
                    'ci_low': float('nan'),
                    'ci_high': float('nan'),
                    'ci_width': float('nan'),
                    'ci_method': self.ci_method,
                    'n_seeds': int(group['seed'].nunique()) if 'seed' in group.columns else int(len(group)),
                    'power_warning': False,
                })

        return cost_rows

    def _build_stats_gate(self, aggregate_df: pd.DataFrame) -> Dict[str, Any]:
        gate_cfg = dict(self.gate_config)
        enforce = bool(gate_cfg.get("enforce", True))
        min_seeds = int(gate_cfg.get("min_seeds", 1))
        required_metrics = list(gate_cfg.get("required_metrics", ["AUROC_final"]))
        max_ci_width = gate_cfg.get("max_ci_width", {}) or {}

        failures: List[Dict[str, Any]] = []
        if enforce:
            for metric in required_metrics:
                metric_rows = aggregate_df[aggregate_df['metric'] == metric]
                if metric_rows.empty:
                    failures.append({
                        "metric": metric,
                        "reason": "missing_required_metric",
                    })
                    continue
                for _, row in metric_rows.iterrows():
                    scenario = row.get("scenario")
                    variant = row.get("variant")
                    method = row.get("method")
                    n_seeds = int(row.get("n_seeds", 0) or 0)
                    if n_seeds < min_seeds:
                        failures.append({
                            "metric": metric,
                            "scenario": scenario,
                            "variant": variant,
                            "method": method,
                            "reason": "insufficient_seeds",
                            "observed": n_seeds,
                            "required": min_seeds,
                        })
                    ci_bound = max_ci_width.get(metric)
                    if ci_bound is not None:
                        ci_width = row.get("ci_width", float('nan'))
                        if np.isfinite(ci_width) and float(ci_width) > float(ci_bound):
                            failures.append({
                                "metric": metric,
                                "scenario": scenario,
                                "variant": variant,
                                "method": method,
                                "reason": "ci_too_wide",
                                "observed": float(ci_width),
                                "required": float(ci_bound),
                            })

        checked_rows = aggregate_df[aggregate_df['metric'].isin(required_metrics)]
        passed = len(failures) == 0
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "suite": self.output_dir.name,
            "output_dir": str(self.output_dir),
            "batch_id": self.batch_id,
            "aggregation_scope": self.aggregation_scope,
            "batch_manifest": str(self.batch_manifest_path),
            "n_records": int(len(self.records)),
            "config": gate_cfg,
            "checked_rows": int(len(checked_rows)),
            "failures": failures,
            "passed": passed,
        }

    def _build_statistics_table(self, df: pd.DataFrame) -> pd.DataFrame:
        stats_rows: List[Dict[str, Any]] = []
        df_metrics = df
        p_values: Dict[Tuple[str, str, str], float] = {}

        for (scenario, variant), slice_df in df_metrics.groupby(['scenario', 'variant']):
            methods = sorted(slice_df['algo'].unique())
            if len(methods) < 2:
                continue
            reference_method = 'ours' if 'ours' in methods else methods[0]
            reference_df = slice_df[slice_df['algo'] == reference_method].rename(columns={'run_dir': f'run_dir_{reference_method}'})

            for method in methods:
                if method == reference_method:
                    continue
                method_df = slice_df[slice_df['algo'] == method].rename(columns={'run_dir': f'run_dir_{method}'})
                merged = reference_df.merge(method_df, on='seed', suffixes=(f'_{reference_method}', f'_{method}'))
                if merged.empty:
                    continue
                for metric in METRIC_COLUMNS:
                    col_a = f'{metric}_{reference_method}'
                    col_b = f'{metric}_{method}'
                    if col_a not in merged.columns or col_b not in merged.columns:
                        continue
                    if col_a not in merged or col_b not in merged:
                        continue
                    required_cols = [col_a, col_b, f'run_dir_{reference_method}', f'run_dir_{method}']
                    for c in required_cols:
                        if c not in merged.columns:
                            merged[c] = np.nan
                    aligned = merged[required_cols].dropna()
                    if aligned.empty:
                        continue
                    a = pd.to_numeric(aligned[col_a], errors='coerce')
                    b = pd.to_numeric(aligned[col_b], errors='coerce')
                    try:
                        stat, p_val = stats.wilcoxon(aligned[col_a], aligned[col_b], zero_method='wilcox', alternative='two-sided')
                    except ValueError:
                        p_val = float('nan')
                    delta = cliffs_delta(aligned[col_a], aligned[col_b])

                    key = (scenario, variant, metric + f'_{method}')
                    p_values[key] = p_val
                    stats_rows.append({
                        'scenario': scenario,
                        'variant': variant,
                        'metric': metric,
                        'reference_method': reference_method,
                        'method': method,
                        'wilcoxon_p': p_val,
                        'cliffs_delta': delta,
                    })

                    if metric == 'AUROC_final':
                        p_delong = self._compute_delong_pvalue(aligned, reference_method, method)
                        stats_rows[-1]['delong_p'] = p_delong
                        if np.isfinite(p_delong):
                            p_values[(scenario, variant, f'delong_{method}')] = p_delong

        adjusted = benjamini_hochberg(p_values)
        for row in stats_rows:
            key = (row['scenario'], row['variant'], row['metric'] + f"_{row['method']}")
            row['wilcoxon_p_adj'] = adjusted.get(key, float('nan'))
            if 'delong_p' in row:
                dkey = (row['scenario'], row['variant'], f"delong_{row['method']}")
                row['delong_p_adj'] = adjusted.get(dkey, float('nan'))

        return pd.DataFrame(stats_rows)

    def _compute_delong_pvalue(self, aligned: pd.DataFrame, reference_method: str, method: str) -> float:
        try:
            base_scores, base_labels = self._collect_trust_predictions(aligned, reference_method)
            method_scores, _ = self._collect_trust_predictions(aligned, method)
            if base_scores.size == 0 or method_scores.size == 0:
                return float('nan')
            return delong_roc_test(base_labels, base_scores, method_scores)
        except Exception:
            return float('nan')

    def _collect_trust_predictions(self, merged: pd.DataFrame, method: str) -> Tuple[np.ndarray, np.ndarray]:
        scores: List[float] = []
        labels: List[int] = []
        for _, row in merged.iterrows():
            run_dir_key = f'run_dir_{method}'
            run_dir = row[run_dir_key] if run_dir_key in row.index else row.get('run_dir')
            if not run_dir:
                continue
            final_trust_path = Path(run_dir) / 'final_trust.csv'
            if not final_trust_path.exists():
                continue
            df = pd.read_csv(final_trust_path)
            if 'trust_score' not in df or 'is_malicious' not in df:
                continue
            scores.extend(1.0 - df['trust_score'].astype(float).tolist())
            labels.extend(df['is_malicious'].astype(int).tolist())
        return np.asarray(scores, dtype=float), np.asarray(labels, dtype=int)


__all__ = ['ExperimentAggregator']
