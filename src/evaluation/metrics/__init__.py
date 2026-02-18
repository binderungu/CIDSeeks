"""Evaluation metrics module for CIDSeeks.

This module provides comprehensive metrics collection and analysis
for CIDS trust methods evaluation. Serves as single source of truth
for all enhanced metrics functionality.
"""

from .enhanced_metrics import (
    EnhancedMetrics,
    DetectionMetrics,
    TrustMetrics,
    PerformanceMetrics,
    AttackResilienceMetrics,
    compute_auroc,
    compute_auprc,
    classification_rates,
    generate_metrics_summary,
    compare_methods_statistically,
    compute_metrics_for_iteration,
    compute_tti_summary,
    compute_trust_gap_auc,
)

__all__ = [
    "EnhancedMetrics",
    "DetectionMetrics", 
    "TrustMetrics",
    "PerformanceMetrics",
    "AttackResilienceMetrics",
    "compute_auroc",
    "compute_auprc", 
    "classification_rates",
    "generate_metrics_summary",
    "compare_methods_statistically",
    "compute_metrics_for_iteration",
    "compute_tti_summary",
    "compute_trust_gap_auc",
]
