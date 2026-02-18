"""Enhanced evaluation metrics for CIDSeeks.

This module centralises all metrics collection and computation for CIDS evaluation.
Serves as single source of truth for enhanced metrics throughout the system.

All functions are intentionally lightweight and return scalars or small
data-structures ready for JSON serialisation and database storage.
"""
from __future__ import annotations

import time
import math
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Sequence, Mapping, Tuple
from collections import defaultdict
from dataclasses import dataclass
import logging

from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
)
from sklearn.linear_model import LogisticRegression
from scipy import stats

# ---------------------------------------------------------------------------
# Data Classes for structured metrics
# ---------------------------------------------------------------------------

@dataclass
class DetectionMetrics:
    """Metrics untuk detection performance."""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total
    
    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def false_positive_rate(self) -> float:
        if self.true_negatives + self.false_positives == 0:
            return 0.0
        return self.false_positives / (self.true_negatives + self.false_positives)

@dataclass
class TrustMetrics:
    """Metrics untuk trust convergence and stability."""
    time_to_demote: float = 0.0
    trust_degradation_speed: float = 0.0
    trust_stability: float = 0.0
    consensus_time: float = 0.0
    convergence_rate: float = 0.0
    undetected_malicious: float = 0.0
    misalignment: float = 0.0

@dataclass
class PerformanceMetrics:
    """Metrics untuk system performance."""
    avg_calculation_time: float = 0.0
    memory_usage: float = 0.0
    cpu_utilization: float = 0.0
    throughput: float = 0.0
    scalability_factor: float = 0.0
    computation_time: float = 0.0

@dataclass
class AttackResilienceMetrics:
    """Metrics untuk attack resilience."""
    pmfa_resilience: float = 0.0
    collusion_detection_rate: float = 0.0
    sybil_detection_rate: float = 0.0
    betrayal_response_time: float = 0.0
    attack_impact_mitigation: float = 0.0
    collusion_error: float = 0.0

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def compute_auroc(labels: Sequence[int], scores: Sequence[float]) -> float:
    """Area under ROC. labels ∈ {0,1}; scores ∈ [0,1] higher ⇒ benign.
    
    AUROC is computed on *malicious probability*, so we invert scores.
    """
    if not labels or len(labels) != len(scores):
        return float("nan")
    y_true = np.asarray(labels, dtype=int)
    if y_true.size < 2 or np.unique(y_true).size < 2:
        # One-class labels do not define a meaningful ROC curve.
        return float("nan")
    
    try:
        # scikit expects positive class — we treat 1 as malicious label.
        malicious_prob = [1.0 - s for s in scores]
        return float(roc_auc_score(y_true, malicious_prob))
    except Exception:
        return float("nan")

def compute_auprc(labels: Sequence[int], scores: Sequence[float]) -> float:
    """Area under Precision-Recall curve (malicious as positive)."""
    if not labels or len(labels) != len(scores):
        return float("nan")
    y_true = np.asarray(labels, dtype=int)
    if y_true.size < 2 or np.unique(y_true).size < 2:
        # Prevent undefined one-class PR behavior and noisy sklearn warnings.
        return float("nan")
    
    try:
        malicious_prob = [1.0 - s for s in scores]
        return float(average_precision_score(y_true, malicious_prob))
    except Exception:
        return float("nan")

def classification_rates(labels: Sequence[int], preds: Sequence[int]) -> Dict[str, float]:
    """Return TP, FP, FN, TN and derived metrics (FNR, recall, precision)."""
    tp = fp = fn = tn = 0
    for y, p in zip(labels, preds):
        if y == 1 and p == 1:
            tp += 1
        elif y == 0 and p == 1:
            fp += 1
        elif y == 1 and p == 0:
            fn += 1
        else:
            tn += 1
    
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fnr = fn / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    fpr = fp / (tn + fp) if (tn + fp) else 0.0
    
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "fnr": fnr,
        "accuracy": accuracy,
        "false_positive_rate": fpr,
    }

# ---------------------------------------------------------------------------
# Main EnhancedMetrics Class
# ---------------------------------------------------------------------------

class EnhancedMetrics:
    """
    Enhanced metrics collection system for comprehensive CIDS evaluation.
    
    Implements unified metric suite covering:
    1. Detection-level metrics
    2. Trust convergence metrics  
    3. Attack resilience metrics
    4. System performance metrics
    
    Single source of truth for all metrics in CIDSeeks system.
    """
    
    def __init__(self, seed: Optional[int] = None):
        self.logger = logging.getLogger("EnhancedMetrics")
        try:
            resolved_seed = 0 if seed is None else int(seed)
        except (TypeError, ValueError):
            resolved_seed = 0
        self.rng = np.random.default_rng(resolved_seed)
        
        # Raw data collection
        self.detection_data: List[Dict[str, Any]] = []
        self.trust_evolution: List[Dict[str, Any]] = []
        self.performance_data: List[Dict[str, Any]] = []
        self.attack_data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Detection counters
        self.tp_count = 0
        self.fp_count = 0
        self.tn_count = 0
        self.fn_count = 0
        
        # Trust tracking
        self.trust_ground_truth: Dict[Any, bool] = {}
        self.trust_estimates: Dict[Any, List[Tuple[int, float]]] = defaultdict(list)
        self.demotion_times: Dict[Any, List[int]] = defaultdict(list)
        self.challenge_outcomes: List[Dict[str, Any]] = []
        
        # Performance tracking
        self.communication_costs: Dict[str, List[float]] = defaultdict(list)
        self.computation_times: Dict[str, List[float]] = defaultdict(list)

        # Run-level runtime stats injected by orchestrator/engine
        self.runtime_stats: Dict[str, Any] = {
            "cpu_time_ms": None,
            "mem_peak_mb": None,
            "run_duration_s": None,
            "total_messages": None,
            "msgs_per_round_mean": None,
            "msgs_per_round_p95": None,
            "msgs_per_round_total": None,
            "latency_ms_samples": [],
            "bootstrap_samples": 10000,
            "tau": 0.5,
            "alpha_star": None,
            "notes": "",
        }

        # Timing
        self.start_time = time.time()
        self.current_iteration = 0

    # ------------------------------------------------------------------
    # Runtime stats helpers (populated by SimulationEngine / orchestrator)
    # ------------------------------------------------------------------
    def update_runtime_stats(self, **stats: Any) -> None:
        """Merge runtime statistics (latency samples, cpu usage, etc.)."""
        for key, value in stats.items():
            if value is None:
                continue
            if key == "latency_ms_samples":
                samples = [float(v) for v in value if v is not None]
                if not samples:
                    continue
                self.runtime_stats.setdefault("latency_ms_samples", [])
                self.runtime_stats["latency_ms_samples"].extend(samples)
            else:
                self.runtime_stats[key] = value

    def reset_runtime_stats(self) -> None:
        """Reset runtime stats to defaults (between independent runs)."""
        keep_bootstrap = self.runtime_stats.get("bootstrap_samples", 10000)
        self.runtime_stats = {
            "cpu_time_ms": None,
            "mem_peak_mb": None,
            "run_duration_s": None,
            "total_messages": None,
            "msgs_per_round_mean": None,
            "msgs_per_round_p95": None,
            "msgs_per_round_total": None,
            "latency_ms_samples": [],
            "bootstrap_samples": keep_bootstrap,
            "tau": self.runtime_stats.get("tau", 0.5),
            "alpha_star": None,
            "notes": "",
        }
        
    def record_detection(self, predicted: float, actual: float, threshold: float = 0.5):
        """Record detection result."""
        self.detection_data.append({
            'predicted': predicted,
            'actual': actual,
            'threshold': threshold,
            'timestamp': time.time()
        })
        
        # Update counters
        pred_label = 1 if predicted < threshold else 0  # Lower trust = malicious
        actual_label = int(actual)
        
        if actual_label == 1 and pred_label == 1:
            self.tp_count += 1
        elif actual_label == 0 and pred_label == 1:
            self.fp_count += 1
        elif actual_label == 1 and pred_label == 0:
            self.fn_count += 1
        else:
            self.tn_count += 1
    
    def record_trust_evolution(self, iteration: int, node_id: str, trust_score: float, 
                              is_malicious: bool = False):
        """Record trust score evolution."""
        self.trust_evolution.append({
            'iteration': iteration,
            'node_id': node_id,
            'trust_score': trust_score,
            'is_malicious': is_malicious,
            'timestamp': time.time()
        })
        
        self.trust_estimates[node_id].append((iteration, trust_score))
        self.trust_ground_truth[node_id] = is_malicious
    
    def record_performance(self, execution_time: float, memory_usage: float, 
                          operation: str = 'trust_calculation'):
        """Record performance metrics."""
        self.performance_data.append({
            'execution_time': execution_time,
            'memory_usage': memory_usage,
            'operation': operation,
            'timestamp': time.time()
        })
        
        self.computation_times[operation].append(execution_time)
    
    def record_attack_impact(self, attack_type: str, impact_score: float, 
                           detection_time: Optional[int] = None):
        """Record attack impact and detection."""
        self.attack_data[attack_type].append({
            'impact_score': impact_score,
            'detection_time': detection_time,
            'timestamp': time.time()
        })

    def record_challenge_outcome(
        self,
        *,
        source_node: int,
        target_node: int,
        iteration: int,
        trust_before: float,
        trust_after: float,
        detection_threshold: float,
        target_is_malicious: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record rich challenge outcome for bypass/stability analytics."""
        payload = {
            'source_node': int(source_node),
            'target_node': int(target_node),
            'iteration': int(iteration),
            'trust_before': float(trust_before),
            'trust_after': float(trust_after),
            'detection_threshold': float(detection_threshold),
            'target_is_malicious': bool(target_is_malicious),
            'timestamp': time.time(),
        }
        if details:
            payload.update(details)
        self.challenge_outcomes.append(payload)
    
    def calculate_detection_metrics(self) -> DetectionMetrics:
        """Calculate detection metrics from recorded data."""
        return DetectionMetrics(
            true_positives=self.tp_count,
            false_positives=self.fp_count,
            true_negatives=self.tn_count,
            false_negatives=self.fn_count
        )
    
    def calculate_trust_metrics(self) -> TrustMetrics:
        """Calculate trust convergence metrics."""
        metrics = TrustMetrics()
        
        if not self.trust_evolution:
            return metrics
        
        # Calculate time to demote (average time for malicious nodes to drop below threshold)
        malicious_demotions = []
        for node_id, is_malicious in self.trust_ground_truth.items():
            if is_malicious and node_id in self.trust_estimates:
                trust_history = self.trust_estimates[node_id]
                for i, (iteration, trust) in enumerate(trust_history):
                    if trust < 0.5:  # Threshold for demotion
                        malicious_demotions.append(iteration)
                        break
        
        if malicious_demotions:
            metrics.time_to_demote = float(np.mean(malicious_demotions))
        
        # Calculate trust degradation speed
        degradation_speeds = []
        for node_id, is_malicious in self.trust_ground_truth.items():
            if is_malicious and node_id in self.trust_estimates:
                trust_history = self.trust_estimates[node_id]
                if len(trust_history) >= 2:
                    initial_trust = trust_history[0][1]
                    final_trust = trust_history[-1][1]
                    iterations = trust_history[-1][0] - trust_history[0][0]
                    if iterations > 0:
                        speed = (initial_trust - final_trust) / iterations
                        degradation_speeds.append(speed)
        
        if degradation_speeds:
            metrics.trust_degradation_speed = float(np.mean(degradation_speeds))
        
        # Calculate undetected malicious (ratio of malicious nodes still trusted)
        undetected_count = 0
        total_malicious = 0
        for node_id, is_malicious in self.trust_ground_truth.items():
            if is_malicious:
                total_malicious += 1
                if node_id in self.trust_estimates:
                    final_trust = self.trust_estimates[node_id][-1][1] if self.trust_estimates[node_id] else 0.5
                    if final_trust >= 0.5:  # Still trusted
                        undetected_count += 1
        
        if total_malicious > 0:
            metrics.undetected_malicious = undetected_count / total_malicious
        
        return metrics
    
    def calculate_attack_resilience_metrics(self) -> AttackResilienceMetrics:
        """Calculate attack resilience metrics."""
        metrics = AttackResilienceMetrics()
        
        # PMFA resilience
        if 'pmfa' in self.attack_data:
            pmfa_impacts = [entry['impact_score'] for entry in self.attack_data['pmfa']]
            if pmfa_impacts:
                metrics.pmfa_resilience = 1.0 - np.mean(pmfa_impacts)
        
        # Collusion detection rate
        if 'collusion' in self.attack_data:
            collusion_detections = [entry for entry in self.attack_data['collusion'] 
                                  if entry['detection_time'] is not None]
            total_collusions = len(self.attack_data['collusion'])
            if total_collusions > 0:
                metrics.collusion_detection_rate = len(collusion_detections) / total_collusions
        
        # Sybil detection rate
        if 'sybil' in self.attack_data:
            sybil_detections = [entry for entry in self.attack_data['sybil'] 
                              if entry['detection_time'] is not None]
            total_sybils = len(self.attack_data['sybil'])
            if total_sybils > 0:
                metrics.sybil_detection_rate = len(sybil_detections) / total_sybils
        
        # Betrayal response time
        if 'betrayal' in self.attack_data:
            betrayal_times = [entry['detection_time'] for entry in self.attack_data['betrayal'] 
                            if entry['detection_time'] is not None]
            if betrayal_times:
                metrics.betrayal_response_time = np.mean(betrayal_times)
        
        return metrics
    
    def calculate_performance_metrics(self) -> PerformanceMetrics:
        """Calculate system performance metrics."""
        metrics = PerformanceMetrics()
        
        if self.performance_data:
            exec_times = [entry['execution_time'] for entry in self.performance_data]
            memories = [entry['memory_usage'] for entry in self.performance_data]
            
            metrics.avg_calculation_time = np.mean(exec_times)
            metrics.computation_time = np.mean(exec_times)
            metrics.memory_usage = np.mean(memories)
            
            # Throughput (operations per second)
            if exec_times:
                metrics.throughput = 1.0 / np.mean(exec_times) if np.mean(exec_times) > 0 else 0.0
        
        return metrics
    
    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """Get all metrics in comprehensive format for database storage."""
        detection_metrics = self.calculate_detection_metrics()
        trust_metrics = self.calculate_trust_metrics()
        resilience_metrics = self.calculate_attack_resilience_metrics()
        performance_metrics = self.calculate_performance_metrics()

        runtime_tau = float(self.runtime_stats.get("tau", 0.5) or 0.5)
        bootstrap_samples = int(self.runtime_stats.get("bootstrap_samples") or 10000)

        # Final trust per node (latest observed value)
        final_trust: Dict[str, float] = {}
        for node_id, history in self.trust_estimates.items():
            if not history:
                continue
            history_sorted = sorted(history, key=lambda x: x[0])
            final_trust[str(node_id)] = float(history_sorted[-1][1])

        # Ensure trust values for nodes present only in trust_evolution
        for rec in self.trust_evolution:
            nid = str(rec.get('node_id'))
            iteration = int(rec.get('iteration', 0))
            trust_val = float(rec.get('trust_score', 0.0))
            if nid not in final_trust or iteration >= len(self.trust_estimates.get(nid, [])):
                final_trust[nid] = trust_val

        # Build lookup for malicious flags (support int/str keys)
        malicious_flags: Dict[str, bool] = {}
        for node_id, flag in self.trust_ground_truth.items():
            bool_flag = bool(flag)
            malicious_flags[str(node_id)] = bool_flag
            try:
                malicious_flags[str(int(node_id))] = bool_flag
            except Exception:
                self.logger.debug("Failed to normalize node_id %s", node_id)

        def _is_malicious(node_key: Any) -> bool:
            if node_key in malicious_flags:
                return malicious_flags[node_key]
            skey = str(node_key)
            if skey in malicious_flags:
                return malicious_flags[skey]
            return False

        # Robustness metrics -------------------------------------------------
        tti_rows = self.compute_tti(tau_drop=runtime_tau)
        tti_values = [float(row['tti']) for row in tti_rows if row.get('tti', -1) >= 0]
        if tti_values:
            tti_array = np.asarray(tti_values, dtype=float)
            tti_mean = float(np.mean(tti_array))
            tti_median = float(np.median(tti_array))
            tti_q1 = float(np.percentile(tti_array, 25))
            tti_q3 = float(np.percentile(tti_array, 75))
            tti_p95 = float(np.percentile(tti_array, 95))
            tti_ci_lower, tti_ci_upper = _bootstrap_ci(
                tti_array.tolist(),
                func=np.median,
                n_resamples=bootstrap_samples,
                rng=self.rng,
            )
        else:
            tti_mean = tti_median = tti_q1 = tti_q3 = tti_p95 = float('nan')
            tti_ci_lower = tti_ci_upper = float('nan')

        total_malicious = 0
        malicious_not_isolated = 0
        total_honest = 0
        honest_quarantined = 0

        for node_key, trust_val in final_trust.items():
            if _is_malicious(node_key):
                total_malicious += 1
                if not math.isnan(trust_val) and trust_val >= runtime_tau:
                    malicious_not_isolated += 1
            else:
                total_honest += 1
                if not math.isnan(trust_val) and trust_val < runtime_tau:
                    honest_quarantined += 1

        asr = float(malicious_not_isolated / total_malicious) if total_malicious > 0 else float('nan')
        fnrq = asr  # False non-quarantine is equivalent to ASR under this definition
        fqr = float(honest_quarantined / total_honest) if total_honest > 0 else float('nan')

        trust_gap_series = self.compute_trust_means()
        trust_gap_final = float(trust_gap_series[-1]['gap']) if trust_gap_series else float('nan')
        trust_gap_auc = float('nan')
        if trust_gap_series:
            try:
                series_df = (
                    pd.DataFrame(trust_gap_series)
                    .assign(
                        round=lambda x: pd.to_numeric(x['round'], errors='coerce'),
                        gap=lambda x: pd.to_numeric(x['gap'], errors='coerce'),
                    )
                    .dropna(subset=['round', 'gap'])
                    .sort_values('round')
                )
                if len(series_df) >= 2:
                    trust_gap_auc = float(
                        np.trapezoid(
                            series_df['gap'].to_numpy(dtype=float),
                            series_df['round'].to_numpy(dtype=float),
                        )
                    )
                else:
                    trust_gap_auc = compute_trust_gap_auc(trust_gap_series)
            except Exception:
                trust_gap_auc = compute_trust_gap_auc(trust_gap_series)

        latency_samples = [float(v) for v in (self.runtime_stats.get('latency_ms_samples') or []) if math.isfinite(float(v))]
        if latency_samples:
            latency_array = np.asarray(latency_samples, dtype=float)
            latency_ms_median = float(np.median(latency_array))
            latency_ms_mean = float(np.mean(latency_array))
            latency_ms_p95 = float(np.percentile(latency_array, 95))
        else:
            latency_ms_median = latency_ms_mean = latency_ms_p95 = float('nan')

        msgs_per_round_mean = self.runtime_stats.get('msgs_per_round_mean')
        msgs_per_round_p95 = self.runtime_stats.get('msgs_per_round_p95')
        msgs_per_round_total = self.runtime_stats.get('msgs_per_round_total')
        total_messages = self.runtime_stats.get('total_messages', msgs_per_round_total)
        run_duration_s = self.runtime_stats.get('run_duration_s')
        throughput = float(total_messages / run_duration_s) if run_duration_s and total_messages is not None and run_duration_s > 0 else float('nan')

        # Flatten structure for database compatibility
        return {
            # Detection metrics (using consistent naming with UI)
            'accuracy': detection_metrics.accuracy,
            'precision': detection_metrics.precision,
            'recall': detection_metrics.recall,
            'f1_score': detection_metrics.f1_score,
            'false_positive_rate': detection_metrics.false_positive_rate,

            # Trust metrics
            'time_to_demote': trust_metrics.time_to_demote,
            'trust_degradation': trust_metrics.trust_degradation_speed,
            'undetected_malicious': trust_metrics.undetected_malicious,
            'misalignment': trust_metrics.misalignment,

            # Attack resilience
            'pmfa_resilience': resilience_metrics.pmfa_resilience,
            'collusion_detection_rate': resilience_metrics.collusion_detection_rate,
            'collusion_error': resilience_metrics.collusion_error,
            'sybil_detection_rate': resilience_metrics.sybil_detection_rate,
            'betrayal_response_time': resilience_metrics.betrayal_response_time,

            # Performance (legacy)
            'computation_time': performance_metrics.computation_time,
            'memory_usage': performance_metrics.memory_usage,
            'throughput': performance_metrics.throughput,

            # Summary counts
            'total_detections': len(self.detection_data),
            'total_trust_records': len(self.trust_evolution),
            'evaluation_duration': time.time() - self.start_time,

            # New robustness metrics
            'tti_mean': tti_mean,
            'tti_median': tti_median,
            'tti_q1': tti_q1,
            'tti_q3': tti_q3,
            'tti_p95': tti_p95,
            'tti_ci_lower': tti_ci_lower,
            'tti_ci_upper': tti_ci_upper,
            'tti_sample_size': len(tti_values),
            'asr': asr,
            'fqr': fqr,
            'fnrq': fnrq,
            'trust_gap_final': trust_gap_final,
            'trust_gap_auc': trust_gap_auc,

            # Overhead / scalability metrics
            'msgs_per_round_mean': msgs_per_round_mean,
            'msgs_per_round_p95': msgs_per_round_p95,
            'latency_ms_median': latency_ms_median,
            'latency_ms_mean': latency_ms_mean,
            'latency_ms_p95': latency_ms_p95,
            'latency_samples_count': len(latency_samples),
            'cpu_time_ms': self.runtime_stats.get('cpu_time_ms'),
            'mem_peak_mb': self.runtime_stats.get('mem_peak_mb'),
            'throughput_msgs_per_sec': throughput,
            'total_messages': total_messages,

            # Placeholder for scenario-level aggregation (computed later)
            'alpha_star': self.runtime_stats.get('alpha_star', float('nan')),
            'notes': self.runtime_stats.get('notes', ""),
        }
    
    # ------------------------------------------------------------------
    # Round-wise metrics derived from trust_evolution
    # ------------------------------------------------------------------
    def compute_auc_per_round(self) -> List[Dict[str, Any]]:
        """Compute AUROC and AUPRC per iteration using recorded trust_evolution.
        Label 1 = malicious. Trust score higher means more honest, so AU* uses 1 - trust.
        """
        if not self.trust_evolution:
            return []
        by_round: Dict[int, Dict[str, list]] = {}
        for rec in self.trust_evolution:
            it = int(rec['iteration'])
            by_round.setdefault(it, {'labels': [], 'scores': []})
            by_round[it]['labels'].append(1 if rec['is_malicious'] else 0)
            by_round[it]['scores'].append(float(rec['trust_score']))

        rows: List[Dict[str, Any]] = []
        for it in sorted(by_round.keys()):
            labels = by_round[it]['labels']
            scores = by_round[it]['scores']
            try:
                auc_roc = compute_auroc(labels, scores)
            except Exception:
                auc_roc = float('nan')
            try:
                auc_pr = compute_auprc(labels, scores)
            except Exception:
                auc_pr = float('nan')
            rows.append({
                'round': int(it),
                'auc_roc': float(auc_roc) if math.isfinite(auc_roc) else float('nan'),
                'auc_pr': float(auc_pr) if math.isfinite(auc_pr) else float('nan'),
                'n_pos': int(sum(labels)),
                'n_neg': int(len(labels) - sum(labels)),
            })
        return rows

    def compute_trust_means(self) -> List[Dict[str, Any]]:
        """Mean trust honest vs malicious and the gap per iteration."""
        if not self.trust_evolution:
            return []
        by_round_h: Dict[int, list] = {}
        by_round_m: Dict[int, list] = {}
        for rec in self.trust_evolution:
            it = int(rec['iteration'])
            if rec['is_malicious']:
                by_round_m.setdefault(it, []).append(float(rec['trust_score']))
            else:
                by_round_h.setdefault(it, []).append(float(rec['trust_score']))

        rows: List[Dict[str, Any]] = []
        for it in sorted(set(by_round_h.keys()) | set(by_round_m.keys())):
            h_vals = by_round_h.get(it, [])
            m_vals = by_round_m.get(it, [])
            mean_h = float(sum(h_vals) / len(h_vals)) if h_vals else float('nan')
            mean_m = float(sum(m_vals) / len(m_vals)) if m_vals else float('nan')
            gap = (mean_h - mean_m) if (math.isfinite(mean_h) and math.isfinite(mean_m)) else float('nan')
            rows.append({
                'round': int(it),
                'mean_honest': mean_h,
                'mean_malicious': mean_m,
                'gap': gap,
            })
        return rows

    def compute_tti(self, tau_drop: float = 0.5) -> List[Dict[str, Any]]:
        """Per-node first round when trust falls below tau_drop. -1 if never."""
        if not self.trust_evolution:
            return []
        series: Dict[str, List[tuple]] = {}
        is_mal: Dict[str, bool] = {}
        for rec in self.trust_evolution:
            nid = str(rec['node_id'])
            series.setdefault(nid, []).append((int(rec['iteration']), float(rec['trust_score'])))
            is_mal[nid] = bool(rec['is_malicious'])
        for nid in series:
            series[nid].sort(key=lambda x: x[0])

        rows: List[Dict[str, Any]] = []
        for nid, hist in series.items():
            tti_val = -1
            for (it, trust) in hist:
                if trust < tau_drop:
                    tti_val = int(it)
                    break
            rows.append({
                'node_id': nid,
                'is_malicious': 1 if is_mal.get(nid, False) else 0,
                'tti': int(tti_val),
                'isolated': 1 if tti_val >= 0 else 0,
            })
        return rows


def compute_trust_gap_auc(series: Sequence[Mapping[str, Any]]) -> float:
    """Compute area under trust gap curve using trapezoidal rule."""
    if not series:
        return float('nan')
    try:
        rounds = np.array([float(item['round']) for item in series], dtype=float)
        gaps = np.array([float(item.get('gap', float('nan'))) for item in series], dtype=float)
    except Exception:
        return float('nan')
    mask = np.isfinite(rounds) & np.isfinite(gaps)
    if np.sum(mask) < 2:
        return float('nan')
    rounds = rounds[mask]
    gaps = gaps[mask]
    try:
        return float(np.trapezoid(gaps, rounds))
    except Exception:
        return float('nan')

    def compute_fp_curve(self, tau: float = 0.5) -> List[Dict[str, Any]]:
        """Confusion tallies and FP/FN rates per iteration at threshold tau."""
        if not self.trust_evolution:
            return []
        by_round: Dict[int, List[tuple]] = {}
        for rec in self.trust_evolution:
            it = int(rec['iteration'])
            by_round.setdefault(it, []).append((float(rec['trust_score']), 1 if rec['is_malicious'] else 0))
        rows: List[Dict[str, Any]] = []
        for it in sorted(by_round.keys()):
            tp = fp = fn = tn = 0
            for trust, label in by_round[it]:
                pred_mal = 1 if trust < tau else 0
                if pred_mal == 1 and label == 1:
                    tp += 1
                elif pred_mal == 1 and label == 0:
                    fp += 1
                elif pred_mal == 0 and label == 1:
                    fn += 1
                else:
                    tn += 1
            denom_fp = (tn + fp) if (tn + fp) > 0 else 1
            denom_fn = (tp + fn) if (tp + fn) > 0 else 1
            rows.append({
                'round': int(it),
                'tp': int(tp),
                'fp': int(fp),
                'tn': int(tn),
                'fn': int(fn),
                'fp_rate': float(fp / denom_fp),
                'fn_rate': float(fn / denom_fn),
            })
        return rows

    def compute_privacy_leakage_auc(
        self,
        y_true_no_dmpo: Sequence[int],
        scores_no_dmpo: Sequence[float],
        y_true_dmpo: Sequence[int],
        scores_dmpo: Sequence[float],
    ) -> Dict[str, float]:
        """
        Compute attacker AUROC to distinguish challenge vs normal from metadata
        before and after DMPO. scores_* are attacker decision scores (higher=challenge).
        """
        try:
            auc_no = float(roc_auc_score(y_true_no_dmpo, scores_no_dmpo))
        except Exception:
            auc_no = float('nan')
        try:
            auc_with = float(roc_auc_score(y_true_dmpo, scores_dmpo))
        except Exception:
            auc_with = float('nan')
        delta = (auc_with - auc_no) if (math.isfinite(auc_with) and math.isfinite(auc_no)) else float('nan')
        return {
            'auc_no_dmpo': auc_no,
            'auc_dmpo': auc_with,
            'delta_auc': delta,
        }
    
    def reset(self):
        """Reset all collected metrics."""
        self.detection_data.clear()
        self.trust_evolution.clear()
        self.performance_data.clear()
        self.attack_data.clear()

        self.tp_count = 0
        self.fp_count = 0
        self.tn_count = 0
        self.fn_count = 0

        self.trust_ground_truth.clear()
        self.trust_estimates.clear()
        self.demotion_times.clear()
        self.communication_costs.clear()
        self.computation_times.clear()
        self.challenge_outcomes.clear()

        self.start_time = time.time()
        self.current_iteration = 0
        self.reset_runtime_stats()

# ---------------------------------------------------------------------------
# Utility functions for external use
# ---------------------------------------------------------------------------

def generate_metrics_summary(metrics_data: Dict[str, Any]) -> str:
    """Generate human-readable summary of metrics."""
    summary = []
    summary.append("=== CIDSeeks Metrics Summary ===")
    summary.append(f"Accuracy: {metrics_data.get('accuracy', 0.0):.3f}")
    summary.append(f"Precision: {metrics_data.get('precision', 0.0):.3f}")
    summary.append(f"Recall: {metrics_data.get('recall', 0.0):.3f}")
    summary.append(f"F1-Score: {metrics_data.get('f1_score', 0.0):.3f}")
    summary.append(f"Time to Demote: {metrics_data.get('time_to_demote', 0.0):.2f} iterations")
    summary.append(f"Computation Time: {metrics_data.get('computation_time', 0.0):.4f} seconds")
    return "\n".join(summary)

def compare_methods_statistically(method1_metrics: Dict[str, Any], 
                                method2_metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two methods statistically."""
    comparison = {}
    
    key_metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'computation_time']
    
    for metric in key_metrics:
        val1 = method1_metrics.get(metric, 0.0)
        val2 = method2_metrics.get(metric, 0.0)
        
        improvement = ((val1 - val2) / val2 * 100) if val2 != 0 else 0.0
        comparison[f'{metric}_improvement_pct'] = improvement
    
    return comparison

# ---------------------------------------------------------------------------
# PMFA leakage dataset builder
# ---------------------------------------------------------------------------

def build_pmfa_leakage_datasets(
    privacy_logs: Sequence[Mapping[str, Any]],
    scoring: str = "heuristic",
    max_iter: int = 200,
) -> Tuple[List[int], List[float], List[int], List[float], Dict[str, int]]:
    """
    Construct attacker datasets (labels, scores) for PMFA leakage AUC.

    Returns:
      (y_true_no_dmpo, scores_no_dmpo, y_true_dmpo, scores_dmpo, stats)

    Dataset policy:
      - Labels: 1=challenge, 0=normal
      - Scores: higher ⇒ more likely challenge (attacker heuristic)
      - No-DMPO set: include all challenge events and normal events with dmpo_enabled=False
      - DMPO set: include all challenge events and normal events with dmpo_enabled=True
    """
    y_no: List[int] = []
    s_no: List[float] = []
    y_dm: List[int] = []
    s_dm: List[float] = []

    num_challenge = 0
    num_normal_no = 0
    num_normal_dmpo = 0

    def attacker_score(ev: Mapping[str, Any]) -> float:
        delay_ms = float(ev.get('delay_ms') or 0.0)
        variant_present = 0.0 if ev.get('variant_id') is None else 1.0
        # Higher score should indicate challenge-like: small delay, no variant
        delay_component = 1.0 - min(1.0, delay_ms / 100.0)
        variant_component = 1.0 - variant_present
        score = 0.6 * delay_component + 0.4 * variant_component
        return max(0.0, min(1.0, score))

    def features(ev: Mapping[str, Any]) -> List[float]:
        delay_ms = float(ev.get('delay_ms') or 0.0)
        variant_present = 0.0 if ev.get('variant_id') is None else 1.0
        payload_size = float(ev.get('payload_size') or 0.0)
        delay_norm = max(0.0, min(1.0, delay_ms / 100.0))
        payload_norm = max(0.0, min(1.0, payload_size / 1024.0))
        return [delay_norm, variant_present, payload_norm]

    # Split events into sets
    no_set: List[Mapping[str, Any]] = []
    dm_set: List[Mapping[str, Any]] = []
    for ev in privacy_logs:
        is_chal = bool(ev.get('is_challenge', False))
        dmpo = bool(ev.get('dmpo_enabled', False))
        if is_chal or not dmpo:
            no_set.append(ev)
        if is_chal or dmpo:
            dm_set.append(ev)

    def score_set(events: Sequence[Mapping[str, Any]]) -> Tuple[List[int], List[float]]:
        y: List[int] = []
        X: List[List[float]] = []
        for ev in events:
            y.append(1 if ev.get('is_challenge', False) else 0)
            X.append(features(ev))
        if scoring == 'logreg':
            try:
                # Check if both classes present
                if len(set(y)) >= 2:
                    clf = LogisticRegression(max_iter=max_iter, solver='liblinear')
                    clf.fit(X, y)
                    scores = clf.predict_proba(X)[:, 1].tolist()
                    return y, [float(s) for s in scores]
            except Exception:
                logger = logging.getLogger("EnhancedMetrics")
                logger.debug("PMFA logreg scoring failed; falling back to heuristic.")
        # Fallback to heuristic or if logreg not applicable
        scores = [attacker_score(ev) for ev in events]
        return y, [float(s) for s in scores]

    y_no, s_no = score_set(no_set)
    y_dm, s_dm = score_set(dm_set)

    # Stats counts
    num_challenge = sum(1 for ev in no_set if ev.get('is_challenge', False))
    num_normal_no = sum(1 for ev in no_set if not ev.get('is_challenge', False))
    num_normal_dmpo = sum(1 for ev in dm_set if not ev.get('is_challenge', False))

    stats = {
        'n_challenge': num_challenge,
        'n_normal_no_dmpo': num_normal_no,
        'n_normal_dmpo': num_normal_dmpo,
    }
    return y_no, s_no, y_dm, s_dm, stats

# ---------------------------------------------------------------------------
# DB-backed round metrics helpers
# ---------------------------------------------------------------------------

def _safe_auc(y_true, y_score):
    y_true = np.asarray(y_true)
    y_score = np.asarray(y_score)
    if len(np.unique(y_true)) < 2 or len(y_true) < 2:
        return float("nan")
    try:
        return float(roc_auc_score(y_true, y_score))
    except Exception:
        return float("nan")

def _safe_aupr(y_true, y_score):
    y_true = np.asarray(y_true)
    y_score = np.asarray(y_score)
    if len(np.unique(y_true)) < 2 or len(y_true) < 2:
        return float("nan")
    try:
        return float(average_precision_score(y_true, y_score))
    except Exception:
        return float("nan")

def compute_metrics_for_iteration(db, iteration: int, tau: float = 0.5) -> dict:
    """Compute and persist per-round metrics using DB data.

    Expects `db` to implement `execute_query(sql, params)` and `store_metric(iter, method, name, value)`.
    """
    # Average trust per target on this iteration
    q = (
        """
        SELECT target_node_id, AVG(score) AS trust
        FROM trust_scores
        WHERE iteration = ?
        GROUP BY target_node_id
        """
    )
    rows = db.execute_query(q, (iteration,)).fetchall()
    if not rows:
        return {}

    trust = {r[0] if isinstance(r, tuple) else r["target_node_id"]: float((r[1] if isinstance(r, tuple) else r["trust"]) or 0.5) for r in rows}

    # Ground truth labels
    g = db.execute_query("SELECT node_id, is_malicious FROM nodes").fetchall()
    y_true: List[int] = []
    y_trust: List[float] = []
    for r in g:
        nid = r[0] if isinstance(r, tuple) else r["node_id"]
        if nid in trust:
            y_true.append(int(r[1] if isinstance(r, tuple) else r["is_malicious"]))
            y_trust.append(float(trust[nid]))

    if not y_true:
        return {}

    y_true_arr = np.asarray(y_true, dtype=int)
    y_trust_arr = np.asarray(y_trust, dtype=float)
    y_score = 1.0 - y_trust_arr  # malicious probability

    auc_roc = _safe_auc(y_true_arr, y_score)
    auc_pr = _safe_aupr(y_true_arr, y_score)

    # Discrete predictions by threshold on trust
    y_pred = (y_trust_arr < tau).astype(int)
    tp = int(np.sum((y_pred == 1) & (y_true_arr == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true_arr == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true_arr == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true_arr == 1)))

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    mean_honest = float(np.mean(y_trust_arr[y_true_arr == 0])) if np.any(y_true_arr == 0) else float("nan")
    mean_malic = float(np.mean(y_trust_arr[y_true_arr == 1])) if np.any(y_true_arr == 1) else float("nan")
    trust_gap = (mean_honest - mean_malic) if math.isfinite(mean_honest) and math.isfinite(mean_malic) else float("nan")

    mal_total = int(np.sum(y_true_arr == 1))
    undetected_ratio = (fn / mal_total) if mal_total > 0 else 0.0

    # Persist to experiment_metrics
    db.store_metric(iteration, "proposed", "auc_roc", auc_roc)
    db.store_metric(iteration, "proposed", "auc_pr", auc_pr)
    db.store_metric(iteration, "proposed", "fp_rate", fpr)
    db.store_metric(iteration, "proposed", "fn_rate", fnr)
    db.store_metric(iteration, "proposed", "mean_trust_honest", mean_honest)
    db.store_metric(iteration, "proposed", "mean_trust_malicious", mean_malic)
    db.store_metric(iteration, "proposed", "trust_gap", trust_gap)
    db.store_metric(iteration, "proposed", "detected_malicious", tp)
    db.store_metric(iteration, "proposed", "undetected_ratio", undetected_ratio)

    return {
        "auc_roc": auc_roc,
        "auc_pr": auc_pr,
        "fpr": fpr,
        "fnr": fnr,
        "mean_trust_honest": mean_honest,
        "mean_trust_malicious": mean_malic,
        "trust_gap": trust_gap,
        "detected_malicious": tp,
        "undetected_ratio": undetected_ratio,
    }

def compute_tti_summary(db, tau: float = 0.5) -> dict:
    """Time-To-Isolate summary for malicious nodes using DB trust scores.

    Returns median and IQR of first iteration where trust < tau.
    """
    rows = db.execute_query("SELECT node_id FROM nodes WHERE is_malicious=1").fetchall()
    mal_ids = [r[0] if isinstance(r, tuple) else r["node_id"] for r in rows]
    tti = []
    for nid in mal_ids:
        q = (
            """
            SELECT MIN(iteration) AS first_hit
            FROM trust_scores
            WHERE target_node_id = ? AND score < ? AND iteration > 0
            """
        )
        row = db.execute_query(q, (nid, float(tau))).fetchone()
        # sqlite3.Row supports key and index access; handle both
        first_hit = None
        if row is not None:
            try:
                first_hit = row[0]
            except Exception:
                try:
                    first_hit = row["first_hit"]
                except Exception:
                    first_hit = None
        if first_hit is not None:
            tti.append(int(first_hit))
    if not tti:
        return {"tti_median": float("nan"), "tti_iqr": float("nan"), "tti_n": 0}
    arr = np.array(tti, dtype=float)
    return {
        "tti_median": float(np.median(arr)),
        "tti_iqr": float(np.percentile(arr, 75) - np.percentile(arr, 25)),
        "tti_n": int(len(arr)),
    }

# ---------------------------------------------------------------
# DB-backed builders for per-run artifacts (stable & reproducible)
# ---------------------------------------------------------------

def _labels_by_node(db) -> Dict[int, int]:
    rows = db.execute_query("SELECT node_id, is_malicious FROM nodes").fetchall()
    mapping: Dict[int, int] = {}
    for r in rows:
        try:
            nid = int(r[0])
            lab = int(r[1])
        except Exception:
            nid = int(r["node_id"])  # type: ignore[index]
            lab = int(r["is_malicious"])  # type: ignore[index]
        mapping[nid] = lab
    return mapping


def _iterations(db) -> List[int]:
    rows = db.execute_query("SELECT DISTINCT iteration FROM trust_scores ORDER BY iteration ASC").fetchall()
    its: List[int] = []
    for r in rows:
        try:
            its.append(int(r[0]))
        except Exception:
            its.append(int(r["iteration"]))  # type: ignore[index]
    return its


def _trust_by_target_for_iter(db, it: int) -> Dict[int, float]:
    q = (
        """
        SELECT target_node_id AS nid, AVG(score) AS trust
        FROM trust_scores
        WHERE iteration = ?
        GROUP BY target_node_id
        """
    )
    rows = db.execute_query(q, (it,)).fetchall()
    out: Dict[int, float] = {}
    for r in rows:
        try:
            nid = int(r[0])
            trust = float(r[1])
        except Exception:
            nid = int(r["nid"])  # type: ignore[index]
            trust = float(r["trust"])  # type: ignore[index]
        out[nid] = trust
    return out


def build_auc_per_round_from_db(db) -> List[Dict[str, Any]]:
    labels = _labels_by_node(db)
    rounds = _iterations(db)
    rows: List[Dict[str, Any]] = []
    for it in rounds:
        trust_map = _trust_by_target_for_iter(db, it)
        if not trust_map:
            continue
        y_true: List[int] = []
        y_score: List[float] = []
        for nid, t in trust_map.items():
            lab = labels.get(nid)
            if lab is None:
                continue
            y_true.append(int(lab))
            # Lower trust => more malicious; use anomaly score = 1 - trust
            y_score.append(float(1.0 - t))
        if not y_true:
            continue
        rows.append(
            {
                "round": it,
                "auc_roc": float(_safe_auc(y_true, y_score)),
                "auc_pr": float(_safe_aupr(y_true, y_score)),
                "n_pos": int(sum(y_true)),
                "n_neg": int(len(y_true) - sum(y_true)),
            }
        )
    return rows


def build_trust_means_from_db(db) -> List[Dict[str, Any]]:
    labels = _labels_by_node(db)
    rounds = _iterations(db)
    rows: List[Dict[str, Any]] = []
    for it in rounds:
        trust_map = _trust_by_target_for_iter(db, it)
        if not trust_map:
            continue
        honest_vals: List[float] = []
        mal_vals: List[float] = []
        for nid, t in trust_map.items():
            lab = labels.get(nid)
            if lab is None:
                continue
            if int(lab) == 1:
                mal_vals.append(float(t))
            else:
                honest_vals.append(float(t))
        mean_honest = float(np.mean(honest_vals)) if honest_vals else float("nan")
        mean_mal = float(np.mean(mal_vals)) if mal_vals else float("nan")
        gap = mean_honest - mean_mal if not np.isnan(mean_honest) and not np.isnan(mean_mal) else float("nan")
        rows.append({"round": it, "mean_honest": mean_honest, "mean_malicious": mean_mal, "gap": gap})
    return rows


def build_fp_curve_from_db(db, tau: float = 0.5) -> List[Dict[str, Any]]:
    labels = _labels_by_node(db)
    rounds = _iterations(db)
    rows: List[Dict[str, Any]] = []
    for it in rounds:
        trust_map = _trust_by_target_for_iter(db, it)
        if not trust_map:
            continue
        tp = fp = tn = fn = 0
        for nid, t in trust_map.items():
            lab = labels.get(nid)
            if lab is None:
                continue
            pred_mal = 1 if float(t) < float(tau) else 0
            if pred_mal == 1 and lab == 1:
                tp += 1
            elif pred_mal == 1 and lab == 0:
                fp += 1
            elif pred_mal == 0 and lab == 1:
                fn += 1
            else:
                tn += 1
        denom_fp = (fp + tn)
        denom_fn = (fn + tp)
        fp_rate = float(fp) / denom_fp if denom_fp > 0 else float("nan")
        fn_rate = float(fn) / denom_fn if denom_fn > 0 else float("nan")
        prec = float(tp) / (tp + fp) if (tp + fp) > 0 else float("nan")
        rec = float(tp) / (tp + fn) if (tp + fn) > 0 else float("nan")
        f1 = 2 * prec * rec / (prec + rec) if (not np.isnan(prec) and not np.isnan(rec) and (prec + rec) > 0) else float("nan")
        rows.append(
            {
                "round": it,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "fp_rate": fp_rate,
                "fn_rate": fn_rate,
                "precision": prec,
                "recall": rec,
                "f1": f1,
            }
        )
    return rows


def _bootstrap_ci(
    data: Sequence[float],
    func=np.median,
    n_resamples: int = 10000,
    ci: float = 0.95,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[float, float]:
    """Generic bootstrap confidence interval helper."""
    arr = np.asarray([float(x) for x in data if math.isfinite(float(x))], dtype=float)
    if arr.size == 0:
        return float('nan'), float('nan')
    if arr.size == 1:
        val = float(func(arr))
        return val, val

    rng = rng or np.random.default_rng(0)
    stats_samples: List[float] = []
    for _ in range(max(1, n_resamples)):
        resample = rng.choice(arr, size=arr.size, replace=True)
        try:
            stats_samples.append(float(func(resample)))
        except Exception:
            continue
    if not stats_samples:
        return float('nan'), float('nan')
    alpha = (1.0 - ci) / 2.0
    lower = float(np.percentile(stats_samples, alpha * 100))
    upper = float(np.percentile(stats_samples, (1.0 - alpha) * 100))
    return lower, upper


def build_tti_from_db(db, tau: float = 0.5) -> List[Dict[str, Any]]:
    # Preload malicious list
    rows_nodes = db.execute_query("SELECT node_id, is_malicious FROM nodes").fetchall()
    labels: Dict[int, int] = {}
    mal_ids: List[int] = []
    for r in rows_nodes:
        try:
            nid = int(r[0]); lab = int(r[1])
        except Exception:
            nid = int(r["node_id"])  # type: ignore[index]
            lab = int(r["is_malicious"])  # type: ignore[index]
        labels[nid] = lab
        if lab == 1:
            mal_ids.append(nid)

    # Compute first hit per node by aggregating avg trust per iter
    q = (
        """
        WITH avg_t AS (
            SELECT target_node_id AS nid, iteration AS it, AVG(score) AS avg_trust
            FROM trust_scores
            GROUP BY target_node_id, iteration
        )
        SELECT nid, MIN(it) AS first_hit
        FROM avg_t
        WHERE avg_trust < ? AND it > 0
        GROUP BY nid
        """
    )
    hits = db.execute_query(q, (float(tau),)).fetchall()
    first_hit_by_nid: Dict[int, int] = {}
    for r in hits:
        try:
            nid = int(r[0]); it = int(r[1])
        except Exception:
            nid = int(r["nid"])  # type: ignore[index]
            it = int(r["first_hit"])  # type: ignore[index]
        first_hit_by_nid[nid] = it

    # Build rows for malicious nodes only (UI filters anyway)
    out: List[Dict[str, Any]] = []
    for nid in mal_ids:
        tti = first_hit_by_nid.get(nid, -1)
        out.append({"node_id": nid, "is_malicious": 1, "tti": int(tti)})
    return out


def build_overhead_timeseries_from_db(db) -> List[Dict[str, Any]]:
    rows = db.execute_query("SELECT iteration, COUNT(*) AS cnt FROM events GROUP BY iteration ORDER BY iteration ASC").fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        try:
            it = int(r[0]); cnt = int(r[1])
        except Exception:
            it = int(r["iteration"])  # type: ignore[index]
            cnt = int(r["cnt"])  # type: ignore[index]
        out.append({"round": it, "msgs": cnt})
    return out


# ---------------------------------------------------------------
# New: Builders for node_round and round_metrics tables
# ---------------------------------------------------------------

def build_node_round_rows(
    db,
    exp_id: str,
    it: int,
    tau: float = 0.5,
) -> List[Dict[str, Any]]:
    """Build per-node record for table node_round at iteration it.

    Requires nodes and trust_scores tables.
    """
    # Load trust avg per node at this iteration
    trust_map = _trust_by_target_for_iter(db, it)
    rows_nodes = db.execute_query("SELECT node_id, is_malicious FROM nodes").fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows_nodes:
        try:
            nid = int(r[0]); is_mal = int(r[1])
        except Exception:
            nid = int(r["node_id"])  # type: ignore[index]
            is_mal = int(r["is_malicious"])  # type: ignore[index]
        tr = float(trust_map.get(nid, float("nan")))
        pred = int(1 if (not math.isnan(tr) and tr < tau) else 0)
        # Determine first detection round (TTD) if any up to current iteration
        ttd_round = None
        try:
            if pred == 1:
                row = db.execute_query(
                    "SELECT MIN(round) AS first_hit FROM node_round WHERE exp_id = ? AND node_id = ? AND pred_is_malicious = 1",
                    (exp_id, nid),
                ).fetchone()
                if row is not None:
                    try:
                        ttd_round = int(row[0]) if row[0] is not None else it
                    except Exception:
                        ttd_round = int(row["first_hit"]) if row["first_hit"] is not None else it  # type: ignore[index]
        except Exception:
            ttd_round = None
        out.append({
            "exp_id": exp_id,
            "round": it,
            "node_id": nid,
            "label_is_malicious": is_mal,
            "trust": tr,
            "pred_is_malicious": pred,
            "was_quarantined": pred,
            "ttd_round": ttd_round,
            "sent_msgs": 0,
            "recv_msgs": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "cpu_ms": None,
            "mem_bytes": None,
        })
    return out


def compute_round_metrics_from_node_round(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate A1/A2 per iteration from node_round-like rows."""
    if not rows:
        return {}
    y_true: List[int] = []
    scores: List[float] = []
    honest_vals: List[float] = []
    mal_vals: List[float] = []
    for r in rows:
        y_true.append(int(r["label_is_malicious"]))
        tr = r.get("trust")
        tr = float(tr) if tr is not None else float("nan")
        scores.append(1.0 - tr if not math.isnan(tr) else float("nan"))
        if r["label_is_malicious"] == 1:
            if not math.isnan(tr):
                mal_vals.append(tr)
        else:
            if not math.isnan(tr):
                honest_vals.append(tr)

    # Filter NaNs
    y = []
    s = []
    for yi, si in zip(y_true, scores):
        if not math.isnan(si):
            y.append(yi); s.append(si)

    auc_node = _safe_auc(y, s) if y else float("nan")
    mean_h = float(sum(honest_vals) / len(honest_vals)) if honest_vals else float("nan")
    mean_m = float(sum(mal_vals) / len(mal_vals)) if mal_vals else float("nan")
    delta_tau = (mean_h - mean_m) if (math.isfinite(mean_h) and math.isfinite(mean_m)) else float("nan")

    # Cohen's d
    def _cohens_d(a: List[float], b: List[float]) -> float:
        if not a or not b:
            return float("nan")
        mu_a = sum(a) / len(a); mu_b = sum(b) / len(b)
        var_a = sum((x - mu_a) ** 2 for x in a) / max(1, (len(a) - 1))
        var_b = sum((x - mu_b) ** 2 for x in b) / max(1, (len(b) - 1))
        s_pooled = math.sqrt(((len(a) - 1) * var_a + (len(b) - 1) * var_b) / max(1, (len(a) + len(b) - 2)))
        if s_pooled == 0:
            return float("nan")
        return (mu_a - mu_b) / s_pooled

    cohens_d = _cohens_d(honest_vals, mal_vals)

    # TPR/FPR per round based on pred_is_malicious
    tp = fp = tn = fn = 0
    for r in rows:
        lab = int(r["label_is_malicious"]) ; pred = int(r["pred_is_malicious"]) 
        if pred == 1 and lab == 1:
            tp += 1
        elif pred == 1 and lab == 0:
            fp += 1
        elif pred == 0 and lab == 0:
            tn += 1
        else:
            fn += 1
    tpr_node = (tp / (tp + fn)) if (tp + fn) > 0 else float("nan")
    fpr_honest = (fp / (fp + tn)) if (fp + tn) > 0 else float("nan")

    # Totals (placeholders; updated when richer logging present)
    total_msgs = sum(int(r.get('sent_msgs') or 0) + int(r.get('recv_msgs') or 0) for r in rows)
    total_bytes = sum(int(r.get('bytes_sent') or 0) + int(r.get('bytes_recv') or 0) for r in rows)

    return {
        "auc_node": float(auc_node),
        "delta_tau": delta_tau,
        "cohens_d": float(cohens_d) if math.isfinite(cohens_d) else float("nan"),
        "tpr_node": tpr_node,
        "fpr_honest": fpr_honest,
        "avg_cpu_ms_node": float('nan'),
        "avg_mem_node": None,
        "total_msgs": int(total_msgs),
        "total_bytes": int(total_bytes),
        "overhead_pct": None,
    }


def compute_fpr_honest_ever_from_db(db, exp_id: str) -> float:
    """Compute ever false isolation rate among honest nodes from node_round."""
    try:
        rows = db.execute_query(
            "SELECT node_id, MAX(CASE WHEN pred_is_malicious=1 THEN 1 ELSE 0 END) AS ever_fp "
            "FROM node_round WHERE exp_id = ? AND label_is_malicious = 0 GROUP BY node_id",
            (exp_id,),
        ).fetchall()
        if not rows:
            return float('nan')
        vals = []
        for r in rows:
            try:
                vals.append(int(r[1]))
            except Exception:
                vals.append(int(r["ever_fp"]))  # type: ignore[index]
        return float(sum(vals) / len(vals)) if vals else float('nan')
    except Exception:
        return float('nan')


def compute_sir_from_db(db, exp_id: str, tau: float = 0.5) -> Dict[str, float]:
    """Compute Sybil infiltration rate and trust share at final round."""
    try:
        r = db.execute_query("SELECT MAX(round) FROM node_round WHERE exp_id = ?", (exp_id,)).fetchone()
        if r is None or (r[0] if not isinstance(r, dict) else r.get('MAX(round)')) is None:
            return {"sir": float('nan'), "trust_share_sybil": float('nan')}
        try:
            last_round = int(r[0])
        except Exception:
            last_round = int(r["MAX(round)"])  # type: ignore[index]
        rows = db.execute_query(
            "SELECT label_is_malicious, trust FROM node_round WHERE exp_id = ? AND round = ?",
            (exp_id, last_round),
        ).fetchall()
        mal_trust = []
        hon_trust = []
        for rr in rows:
            try:
                lab = int(rr[0]); tr = float(rr[1])
            except Exception:
                lab = int(rr["label_is_malicious"])  # type: ignore[index]
                tr = float(rr["trust"])  # type: ignore[index]
            if lab == 1:
                mal_trust.append(tr)
            else:
                hon_trust.append(tr)
        total_mal = len(mal_trust)
        if total_mal == 0:
            return {"sir": float('nan'), "trust_share_sybil": float('nan')}
        # Infiltration = fraction of malicious (sybil) with trust >= tau
        sir = float(sum(1 for t in mal_trust if (not math.isnan(t) and t >= tau)) / total_mal)
        total_trust = sum([t for t in mal_trust if not math.isnan(t)]) + sum([t for t in hon_trust if not math.isnan(t)])
        trust_share_sybil = float(sum([t for t in mal_trust if not math.isnan(t)]) / total_trust) if total_trust > 0 else float('nan')
        return {"sir": sir, "trust_share_sybil": trust_share_sybil}
    except Exception:
        return {"sir": float('nan'), "trust_share_sybil": float('nan')}


def compute_membership_advantage_from_leakage(leak: Dict[str, float]) -> Dict[str, float]:
    """Return (adv_no_dmpo, adv_dmpo) where advantage = 2*AUC - 1."""
    try:
        auc_no_raw = leak.get('auc_no_dmpo')
        auc_dm_raw = leak.get('auc_dmpo')
        auc_no = float(auc_no_raw) if auc_no_raw is not None else float('nan')
        auc_dm = float(auc_dm_raw) if auc_dm_raw is not None else float('nan')
    except Exception:
        auc_no = float('nan')
        auc_dm = float('nan')
    adv_no = (2.0 * auc_no - 1.0) if math.isfinite(auc_no) else float('nan')
    adv_dm = (2.0 * auc_dm - 1.0) if math.isfinite(auc_dm) else float('nan')
    return {"mi_adv_no": adv_no, "mi_adv_dmpo": adv_dm}


def build_round_metrics_for_exp(db, exp_id: str) -> List[Dict[str, Any]]:
    """Return all rows from round_metrics for a given exp_id."""
    rows = db.execute_query(
        "SELECT round, auc_node, delta_tau, cohens_d, tpr_node, fpr_honest, avg_cpu_ms_node, avg_mem_node, total_msgs, total_bytes, overhead_pct, consensus_p50_ms, consensus_p95_ms, ledger_growth_bytes "
        "FROM round_metrics WHERE exp_id = ? ORDER BY round ASC",
        (exp_id,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        try:
            out.append({
                'round': int(r[0]), 'auc_node': r[1], 'delta_tau': r[2], 'cohens_d': r[3], 'tpr_node': r[4], 'fpr_honest': r[5],
                'avg_cpu_ms_node': r[6], 'avg_mem_node': r[7], 'total_msgs': r[8], 'total_bytes': r[9], 'overhead_pct': r[10],
                'consensus_p50_ms': r[11], 'consensus_p95_ms': r[12], 'ledger_growth_bytes': r[13]
            })
        except Exception:
            out.append({
                'round': int(r['round']),
                'auc_node': r.get('auc_node'),
                'delta_tau': r.get('delta_tau'),
                'cohens_d': r.get('cohens_d'),
                'tpr_node': r.get('tpr_node'),
                'fpr_honest': r.get('fpr_honest'),
                'avg_cpu_ms_node': r.get('avg_cpu_ms_node'),
                'avg_mem_node': r.get('avg_mem_node'),
                'total_msgs': r.get('total_msgs'),
                'total_bytes': r.get('total_bytes'),
                'overhead_pct': r.get('overhead_pct'),
                'consensus_p50_ms': r.get('consensus_p50_ms'),
                'consensus_p95_ms': r.get('consensus_p95_ms'),
                'ledger_growth_bytes': r.get('ledger_growth_bytes'),
            })
    return out


def build_node_round_for_exp(db, exp_id: str) -> List[Dict[str, Any]]:
    """Return all rows from node_round for export; potentially large."""
    rows = db.execute_query(
        "SELECT round, node_id, label_is_malicious, trust, pred_is_malicious, was_quarantined, ttd_round, sent_msgs, recv_msgs, bytes_sent, bytes_recv, cpu_ms, mem_bytes "
        "FROM node_round WHERE exp_id = ? ORDER BY round ASC, node_id ASC",
        (exp_id,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        try:
            out.append({
                'round': int(r[0]), 'node_id': int(r[1]), 'label_is_malicious': int(r[2]), 'trust': r[3], 'pred_is_malicious': int(r[4]),
                'was_quarantined': int(r[5]), 'ttd_round': (None if r[6] is None else int(r[6])), 'sent_msgs': int(r[7]), 'recv_msgs': int(r[8]),
                'bytes_sent': int(r[9]), 'bytes_recv': int(r[10]), 'cpu_ms': (None if r[11] is None else float(r[11])), 'mem_bytes': (None if r[12] is None else int(r[12]))
            })
        except Exception:
            out.append({
                'round': int(r['round']), 'node_id': int(r['node_id']), 'label_is_malicious': int(r['label_is_malicious']), 'trust': float(r['trust']),
                'pred_is_malicious': int(r['pred_is_malicious']), 'was_quarantined': int(r['was_quarantined']), 'ttd_round': r.get('ttd_round'),
                'sent_msgs': int(r.get('sent_msgs') or 0), 'recv_msgs': int(r.get('recv_msgs') or 0),
                'bytes_sent': int(r.get('bytes_sent') or 0), 'bytes_recv': int(r.get('bytes_recv') or 0),
                'cpu_ms': r.get('cpu_ms'), 'mem_bytes': r.get('mem_bytes'),
            })
    return out
