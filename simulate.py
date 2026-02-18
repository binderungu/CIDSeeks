"""CLI helper to execute multi-scenario simulations and export metrics.

Usage:
    python simulate.py --suite <smoke|paper_core|robustness_sensitivity|scalability_stress> --config configs/experiments/experiments.yaml

The configuration file defines scenario grids, number of runs per variant,
output locations, and thresholds for the aggregated evaluation. The script
orchestrates SimulationEngine runs, collects enhanced metrics, and uses
ExperimentAggregator to produce experiments.csv, aggregate_summary.csv,
run_log.jsonl, stats_gate.json, seed_manifest.json, and optional suite-level plots.
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

import pandas as pd
import yaml
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'src'
EXPERIMENT_CONFIG_DIR = ROOT / "configs" / "experiments"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from evaluation.export.experiment_aggregator import ExperimentAggregator
from simulation.core.simulation_engine import SimulationEngine


LOGGER = logging.getLogger("simulate")


SUITE_REPRO_POLICY: Dict[str, Dict[str, Any]] = {
    "smoke": {
        "min_runs_per_variant": 1,
        "require_explicit_seed": True,
    },
    "paper_core": {
        "min_runs_per_variant": 10,
        "require_explicit_seed": True,
    },
    "robustness_sensitivity": {
        "min_runs_per_variant": 10,
        "require_explicit_seed": True,
    },
    "scalability_stress": {
        "min_runs_per_variant": 10,
        "require_explicit_seed": True,
    },
}


def _load_yaml(path: Union[str, Path]) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Configuration {path} must be a mapping at the root")
    return data


def _resolve_experiments_config_path(path: Union[str, Path]) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate
    fallback = EXPERIMENT_CONFIG_DIR / candidate.name
    if fallback.exists():
        LOGGER.warning(
            "Deprecated config path resolution: %s not found, using fallback %s. "
            "Please pass canonical path under configs/experiments/.",
            candidate,
            fallback,
        )
        return fallback
    raise FileNotFoundError(
        f"Experiment config not found: {candidate} "
        f"(checked fallback: {fallback})"
    )


def _ensure_nested(mapping: Dict[str, Any], keys: Iterable[str]) -> Dict[str, Any]:
    current = mapping
    for key in keys:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    return current


def _coerce_challenge_rate(value: Any) -> float:
    """Convert challenge rate aliases to numeric values."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        presets = {
            "low": 0.05,
            "med": 0.10,
            "medium": 0.10,
            "high": 0.20,
        }
        lowered = value.strip().lower()
        if lowered in presets:
            return presets[lowered]
        try:
            return float(value)
        except ValueError as exc:
            raise ValueError(f"Unsupported challenge_rate alias: {value}") from exc
    raise TypeError(f"challenge_rate must be numeric or preset string, got {type(value)}")


def _apply_variant(
    base: Dict[str, Any],
    variant: Dict[str, Any],
    scenario: Dict[str, Any],
    seed: int,
    experiment_id: str,
    run_uid: str,
) -> Dict[str, Any]:
    cfg = copy.deepcopy(base)

    sim_cfg = _ensure_nested(cfg, ["simulation"])
    net_cfg = _ensure_nested(cfg, ["network"])
    trust_cfg = _ensure_nested(cfg, ["trust_model"])
    attack_cfg = _ensure_nested(cfg, ["attack"])
    auth_cfg = _ensure_nested(cfg, ["auth"])
    feature_cfg = _ensure_nested(cfg, ["features"])
    eval_cfg = _ensure_nested(cfg, ["evaluation"])

    sim_cfg["name"] = scenario.get("scenario_id")
    sim_cfg["experiment_id"] = experiment_id
    sim_cfg["run_uid"] = run_uid
    sim_cfg["run_id"] = f"{experiment_id}__{run_uid}"
    sim_cfg["seed"] = seed

    if "n_nodes" in variant:
        sim_cfg["total_nodes"] = int(variant["n_nodes"])
    if "iterations" in variant:
        sim_cfg["iterations"] = int(variant["iterations"])
    if "fraction_colluders" in variant:
        ratio = float(variant["fraction_colluders"])
        sim_cfg["malicious_ratio"] = ratio
        attack_cfg["collusion_ratio"] = ratio
    if "malicious_ratio" in variant:
        sim_cfg["malicious_ratio"] = float(variant["malicious_ratio"])
    if "fraction_sybils" in variant:
        attack_cfg["sybil_ratio"] = float(variant["fraction_sybils"])
    if "attack_type" in variant:
        attack_cfg["type"] = variant["attack_type"]
    elif scenario.get("attack_type"):
        attack_cfg["type"] = scenario["attack_type"]

    if "challenge_rate" in variant:
        resolved_rate = _coerce_challenge_rate(variant["challenge_rate"])
        trust_cfg["challenge_rate"] = resolved_rate
        existing_tiers = trust_cfg.get("challenge_rate_tiers")
        # Preserve explicit per-tier schedule from base config unless tiers are absent.
        if not isinstance(existing_tiers, dict) or not existing_tiers:
            trust_cfg["challenge_rate_tiers"] = {
                "basic": resolved_rate,
                "advanced": resolved_rate,
                "final": resolved_rate,
            }
    tier_rate_overrides = {}
    if "challenge_rate_basic" in variant:
        tier_rate_overrides["basic"] = _coerce_challenge_rate(variant["challenge_rate_basic"])
    if "challenge_rate_advanced" in variant:
        tier_rate_overrides["advanced"] = _coerce_challenge_rate(variant["challenge_rate_advanced"])
    if "challenge_rate_final" in variant:
        tier_rate_overrides["final"] = _coerce_challenge_rate(variant["challenge_rate_final"])
    if tier_rate_overrides:
        trust_cfg.setdefault("challenge_rate_tiers", {})
        trust_cfg["challenge_rate_tiers"].update(tier_rate_overrides)
    tier_interval_overrides = {}
    if "challenge_interval_basic" in variant:
        tier_interval_overrides["basic"] = int(variant["challenge_interval_basic"])
    if "challenge_interval_advanced" in variant:
        tier_interval_overrides["advanced"] = int(variant["challenge_interval_advanced"])
    if "challenge_interval_final" in variant:
        tier_interval_overrides["final"] = int(variant["challenge_interval_final"])
    if tier_interval_overrides:
        trust_cfg.setdefault("challenge_min_interval_tiers", {})
        trust_cfg["challenge_min_interval_tiers"].update(tier_interval_overrides)
    if "forgetting_factor" in variant:
        trust_cfg["forgetting_factor"] = float(variant["forgetting_factor"])
    if "trust_threshold" in variant:
        trust_cfg["trust_threshold"] = float(variant["trust_threshold"])
    if "trust_fall_threshold" in variant:
        trust_cfg["trust_fall_threshold"] = float(variant["trust_fall_threshold"])
    if "trust_rise_threshold" in variant:
        trust_cfg["trust_rise_threshold"] = float(variant["trust_rise_threshold"])
    if "trust_model" in variant:
        trust_cfg["method"] = variant["trust_model"]
    if "betrayal_iteration" in variant:
        attack_cfg["betrayal_iteration"] = int(variant["betrayal_iteration"])
    if "betrayal_start_round" in variant:
        attack_cfg["betrayal_start_round"] = int(variant["betrayal_start_round"])
    if "betrayal_mode" in variant:
        attack_cfg["betrayal_mode"] = str(variant["betrayal_mode"])
    if "on_off_period" in variant:
        attack_cfg["on_off_period"] = int(variant["on_off_period"])
    if "on_off_duty_cycle" in variant:
        attack_cfg["on_off_duty_cycle"] = float(variant["on_off_duty_cycle"])

    if "rating_min" in variant:
        attack_cfg["rating_min"] = float(variant["rating_min"])
    if "rating_max" in variant:
        attack_cfg["rating_max"] = float(variant["rating_max"])
    if "honest_rating_mean" in variant:
        attack_cfg["honest_rating_mean"] = float(variant["honest_rating_mean"])
    if "honest_rating_std" in variant:
        attack_cfg["honest_rating_std"] = float(variant["honest_rating_std"])
    if "malicious_high" in variant:
        attack_cfg["malicious_high"] = float(variant["malicious_high"])
    if "malicious_low" in variant:
        attack_cfg["malicious_low"] = float(variant["malicious_low"])
    if "sybil_cluster_size" in variant:
        attack_cfg["sybil_cluster_size"] = int(variant["sybil_cluster_size"])
    if "collusion_group_size" in variant:
        attack_cfg["collusion_group_size"] = int(variant["collusion_group_size"])
    if "pmfa_detect_prob" in variant:
        attack_cfg["pmfa_detect_prob"] = float(variant["pmfa_detect_prob"])
    if "pmfa_collusion_enabled" in variant:
        attack_cfg["pmfa_collusion_enabled"] = bool(variant["pmfa_collusion_enabled"])
    if "pmfa_match_window_rounds" in variant:
        attack_cfg["pmfa_match_window_rounds"] = int(variant["pmfa_match_window_rounds"])
    if "pmfa_min_matches" in variant:
        attack_cfg["pmfa_min_matches"] = int(variant["pmfa_min_matches"])
    if "pmfa_strategy" in variant:
        attack_cfg["pmfa_strategy"] = str(variant["pmfa_strategy"])
    if "pmfa_poison_rate" in variant:
        attack_cfg["pmfa_poison_rate"] = float(variant["pmfa_poison_rate"])
    if "pmfa_fallback_mode" in variant:
        attack_cfg["pmfa_fallback_mode"] = str(variant["pmfa_fallback_mode"])
    if "pmfa_request_prior" in variant:
        attack_cfg["pmfa_request_prior"] = float(variant["pmfa_request_prior"])
    if "pmfa_dmpo_resistance" in variant:
        attack_cfg["pmfa_dmpo_resistance"] = float(variant["pmfa_dmpo_resistance"])
    if "sybil_virtual_identities" in variant:
        attack_cfg["sybil_virtual_identities"] = int(variant["sybil_virtual_identities"])
    if "sybil_identity_rotation" in variant:
        attack_cfg["sybil_identity_rotation"] = str(variant["sybil_identity_rotation"])
    if "sybil_allow_identity_with_auth" in variant:
        attack_cfg["sybil_allow_identity_with_auth"] = bool(variant["sybil_allow_identity_with_auth"])

    if "auth_mode" in variant:
        auth_cfg["mode"] = str(variant["auth_mode"])
    if "auth_ca_name" in variant:
        auth_cfg["ca_name"] = str(variant["auth_ca_name"])
    if "auth_certificate_ttl_rounds" in variant:
        auth_cfg["certificate_ttl_rounds"] = int(variant["auth_certificate_ttl_rounds"])
    if "auth_transport_failure_rate" in variant:
        auth_cfg["transport_failure_rate"] = float(variant["auth_transport_failure_rate"])
    if "auth_false_accept_rate" in variant:
        auth_cfg["verification_false_accept_rate"] = float(variant["auth_false_accept_rate"])
    if "auth_false_reject_rate" in variant:
        auth_cfg["verification_false_reject_rate"] = float(variant["auth_false_reject_rate"])
    if "auth_revocation_enabled" in variant:
        auth_cfg["revocation_enabled"] = bool(variant["auth_revocation_enabled"])
    if "auth_revocation_delay_rounds" in variant:
        auth_cfg["revocation_delay_rounds"] = int(variant["auth_revocation_delay_rounds"])
    if "auth_revocation_epoch_rounds" in variant:
        auth_cfg["revocation_epoch_rounds"] = int(variant["auth_revocation_epoch_rounds"])
    if "auth_revocation_rate_malicious" in variant:
        auth_cfg["revocation_rate_malicious"] = float(variant["auth_revocation_rate_malicious"])
    if "auth_revocation_rate_honest" in variant:
        auth_cfg["revocation_rate_honest"] = float(variant["auth_revocation_rate_honest"])

    if "dirichlet_prior_strength" in variant:
        trust_cfg["dirichlet_prior_strength"] = float(variant["dirichlet_prior_strength"])
    if "dirichlet_forgetting_factor" in variant:
        trust_cfg["dirichlet_forgetting_factor"] = float(variant["dirichlet_forgetting_factor"])
    if "dirichlet_neighbor_blend" in variant:
        trust_cfg["dirichlet_neighbor_blend"] = float(variant["dirichlet_neighbor_blend"])

    if "network_type" in variant:
        net_cfg["type"] = str(variant["network_type"])
    if "connection_probability" in variant:
        net_cfg["connection_probability"] = float(variant["connection_probability"])
    if "neighbors_per_node" in variant:
        net_cfg["neighbors_per_node"] = int(variant["neighbors_per_node"])
    if "rewiring_probability" in variant:
        net_cfg["rewiring_probability"] = float(variant["rewiring_probability"])
    if "neighbors_to_attach" in variant:
        net_cfg["neighbors_to_attach"] = int(variant["neighbors_to_attach"])
    if "hybrid_backbone" in variant:
        net_cfg["hybrid_backbone"] = str(variant["hybrid_backbone"])
    if "hybrid_core_ratio" in variant:
        net_cfg["hybrid_core_ratio"] = float(variant["hybrid_core_ratio"])
    if "hybrid_bridge_probability" in variant:
        net_cfg["hybrid_bridge_probability"] = float(variant["hybrid_bridge_probability"])

    if "gossip_fanout" in variant:
        fanout = variant["gossip_fanout"]
        if isinstance(fanout, str):
            feature_cfg["gossip_fanout"] = fanout
        else:
            feature_cfg["gossip_fanout"] = int(fanout)
    if "gossip_max_hops" in variant:
        feature_cfg["gossip_max_hops"] = int(variant["gossip_max_hops"])
    if "min_alarm_send_delay" in variant:
        feature_cfg["min_alarm_send_delay"] = float(variant["min_alarm_send_delay"])
    if "max_alarm_send_delay" in variant:
        feature_cfg["max_alarm_send_delay"] = float(variant["max_alarm_send_delay"])
    if "variants_per_alarm" in variant:
        feature_cfg["variants_per_alarm"] = int(variant["variants_per_alarm"])
    if "privacy_prefix_bits" in variant:
        feature_cfg["privacy_prefix_bits"] = int(variant["privacy_prefix_bits"])
    if "privacy_k_anonymity" in variant:
        feature_cfg["privacy_k_anonymity"] = int(variant["privacy_k_anonymity"])
    if "dmpo_pmfa_guard" in variant:
        feature_cfg["dmpo_pmfa_guard"] = bool(variant["dmpo_pmfa_guard"])

    if "fraction_sybils" not in variant and scenario.get("fraction_sybils") is not None:
        attack_cfg["sybil_ratio"] = float(scenario.get("fraction_sybils"))
    if "malicious_ratio" not in variant and scenario.get("malicious_ratio") is not None:
        sim_cfg["malicious_ratio"] = float(scenario.get("malicious_ratio"))

    eval_cfg["scenario_notes"] = scenario.get("notes")

    variant_label = _make_variant_label(
        scenario.get("scenario_id", "scenario"),
        variant,
        trust_cfg.get("method"),
        attack_cfg.get("type"),
    )
    sim_cfg["variant"] = variant_label

    return cfg


def _variant_combinations(parameter_grid: Dict[str, Iterable[Any]]) -> Iterator[Dict[str, Any]]:
    if not parameter_grid:
        yield {}
        return
    keys = sorted(parameter_grid.keys())
    values = [list(parameter_grid[k]) for k in keys]
    for combo in itertools.product(*values):
        yield {k: combo[idx] for idx, k in enumerate(keys)}


def _sanitize_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}".replace('.', 'p')
    if isinstance(value, (int, bool)):
        return str(value)
    return str(value).replace(' ', '-').replace('.', '_')


def _make_variant_label(scenario_id: str, variant: Dict[str, Any], trust_method: Optional[str], attack_type: Optional[str]) -> str:
    prefix_parts = []
    if trust_method:
        prefix_parts.append(trust_method)
    if attack_type:
        prefix_parts.append(f"attack-{attack_type}")
    prefix = "_".join(prefix_parts) if prefix_parts else scenario_id
    if not variant:
        return f"{prefix}_baseline"
    kv_pairs = [f"{key}-{_sanitize_value(value)}" for key, value in sorted(variant.items())]
    return f"{prefix}_" + "_".join(kv_pairs)


def _suite_output_root(suite: str) -> Path:
    return Path("results") / suite


def _make_batch_uid() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _scenario_has_explicit_seed(config: Dict[str, Any], scenario: Dict[str, Any]) -> bool:
    if isinstance(scenario.get("seeds"), list) and scenario.get("seeds"):
        return True
    if "seed_start" in scenario:
        return True
    return "seed_start" in config


def _resolve_seed_for_run(
    config: Dict[str, Any],
    scenario: Dict[str, Any],
    variant_index: int,
    run_index: int,
    runs_per_variant: int,
) -> int:
    seeds_override = scenario.get("seeds")
    if seeds_override and run_index < len(seeds_override):
        return int(seeds_override[run_index])
    base_seed = int(scenario.get("seed_start", config.get("seed_start", 0)))
    seed_stride = int(scenario.get("seed_stride", runs_per_variant))
    return int(base_seed + variant_index * seed_stride + run_index)


def _validate_reproducibility_requirements(config: Dict[str, Any], suite: str) -> None:
    policy = SUITE_REPRO_POLICY.get(suite, {})
    gate_cfg = config.get("reproducibility_gate", {}) if isinstance(config.get("reproducibility_gate"), dict) else {}
    if gate_cfg.get("enforce") is False:
        return
    min_runs = int(gate_cfg.get("min_runs_per_variant", policy.get("min_runs_per_variant", 1)))
    require_explicit_seed = bool(gate_cfg.get("require_explicit_seed", policy.get("require_explicit_seed", False)))

    scenarios = config.get("scenarios", [])
    if not scenarios:
        raise ValueError("Configuration must include at least one scenario entry")

    root_runs = int(config.get("runs_per_variant", 1))
    root_has_seed = "seed_start" in config
    if require_explicit_seed and not root_has_seed:
        missing = []
        for scenario in scenarios:
            scenario_id = scenario.get("scenario_id", "<unknown>")
            if not _scenario_has_explicit_seed(config, scenario):
                missing.append(scenario_id)
        if missing:
            raise ValueError(
                "Explicit seed policy violation. Missing seed_start/seeds for scenarios: "
                + ", ".join(missing)
            )

    weak_runs: List[str] = []
    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "<unknown>")
        runs = int(scenario.get("runs_per_variant", root_runs))
        if runs < min_runs:
            weak_runs.append(f"{scenario_id}(runs_per_variant={runs})")
    if weak_runs:
        raise ValueError(
            f"Reproducibility gate failed for suite '{suite}': "
            f"runs_per_variant must be >= {min_runs}. "
            + ", ".join(weak_runs)
        )


def _build_seed_plan(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    scenarios = config.get("scenarios", [])
    root_runs = int(config.get("runs_per_variant", 1))
    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id")
        if not scenario_id:
            raise ValueError("scenario_id is required for each scenario")
        parameter_grid = scenario.get("parameters", {})
        runs_per_variant = int(scenario.get("runs_per_variant", root_runs))
        for variant_index, variant in enumerate(_variant_combinations(parameter_grid)):
            for run_index in range(runs_per_variant):
                seed = _resolve_seed_for_run(
                    config,
                    scenario,
                    variant_index,
                    run_index,
                    runs_per_variant,
                )
                plan.append(
                    {
                        "scenario_id": scenario_id,
                        "variant_index": int(variant_index),
                        "run_index": int(run_index),
                        "seed": int(seed),
                        "variant": dict(variant),
                    }
                )
    return plan


def _write_seed_manifest(
    output_root: Path,
    suite: str,
    config_path: Union[str, Path],
    seed_plan: List[Dict[str, Any]],
) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    payload = {
        "suite": suite,
        "config_path": str(config_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_runs": int(len(seed_plan)),
        "unique_seed_count": int(len({item["seed"] for item in seed_plan})),
        "seed_plan": seed_plan,
    }
    seed_manifest_path = output_root / "seed_manifest.json"
    seed_manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _save_fallback_plot(path: Path, title: str) -> None:
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.text(0.5, 0.5, 'Insufficient data', ha='center', va='center')
    ax.set_title(title)
    ax.set_axis_off()
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _generate_suite_plots(summary_df: pd.DataFrame, output_root: Path) -> None:
    plot_dir = output_root / "aggregate_plots"
    plot_dir.mkdir(parents=True, exist_ok=True)

    if summary_df.empty:
        for name, title in (
            ("fig_accuracy_vs_malicious_ratio.pdf", "Accuracy vs Malicious Ratio"),
            ("fig_overhead_vs_N.pdf", "Overhead vs N"),
            ("fig_latency_vs_N.pdf", "Latency vs N"),
            ("fig_trust_separation.pdf", "Trust Separation"),
            ("fig_pmfa_resistance.pdf", "PMFA Resistance"),
        ):
            _save_fallback_plot(plot_dir / name, title)
        return

    # Accuracy vs malicious ratio
    if 'malicious_ratio' in summary_df.columns:
        metric = 'AUROC_mean' if 'AUROC_mean' in summary_df.columns else 'accuracy'
        if metric in summary_df.columns:
            grouped = summary_df.groupby('malicious_ratio')[metric].mean().reset_index()
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(grouped['malicious_ratio'], grouped[metric], marker='o')
            ax.set_xlabel('malicious_ratio')
            ax.set_ylabel(metric)
            ax.set_title('Accuracy vs Malicious Ratio')
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            fig.savefig(plot_dir / "fig_accuracy_vs_malicious_ratio.pdf", dpi=160)
            plt.close(fig)
        else:
            _save_fallback_plot(plot_dir / "fig_accuracy_vs_malicious_ratio.pdf", "Accuracy vs Malicious Ratio")
    else:
        _save_fallback_plot(plot_dir / "fig_accuracy_vs_malicious_ratio.pdf", "Accuracy vs Malicious Ratio")

    # Overhead vs N
    if 'N' in summary_df.columns:
        metric = 'msgs_per_round_mean' if 'msgs_per_round_mean' in summary_df.columns else 'bytes_per_round_mean'
        if metric in summary_df.columns:
            grouped = summary_df.groupby('N')[metric].mean().reset_index()
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(grouped['N'], grouped[metric], marker='o')
            ax.set_xlabel('N')
            ax.set_ylabel(metric)
            ax.set_title('Overhead vs N')
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            fig.savefig(plot_dir / "fig_overhead_vs_N.pdf", dpi=160)
            plt.close(fig)
        else:
            _save_fallback_plot(plot_dir / "fig_overhead_vs_N.pdf", "Overhead vs N")
    else:
        _save_fallback_plot(plot_dir / "fig_overhead_vs_N.pdf", "Overhead vs N")

    # Latency vs N
    if 'N' in summary_df.columns and 'latency_per_round_mean' in summary_df.columns:
        grouped = summary_df.groupby('N')['latency_per_round_mean'].mean().reset_index()
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot(grouped['N'], grouped['latency_per_round_mean'], marker='o')
        ax.set_xlabel('N')
        ax.set_ylabel('latency_per_round_mean')
        ax.set_title('Latency vs N')
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(plot_dir / "fig_latency_vs_N.pdf", dpi=160)
        plt.close(fig)
    else:
        _save_fallback_plot(plot_dir / "fig_latency_vs_N.pdf", "Latency vs N")

    # Trust separation
    if 'trust_gap_final' in summary_df.columns:
        grouped = summary_df.groupby('N')['trust_gap_final'].mean().reset_index() if 'N' in summary_df.columns else summary_df
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot(grouped.get('N', grouped.index), grouped['trust_gap_final'], marker='o')
        ax.set_xlabel('N' if 'N' in grouped.columns else 'run')
        ax.set_ylabel('trust_gap_final')
        ax.set_title('Trust Separation')
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(plot_dir / "fig_trust_separation.pdf", dpi=160)
        plt.close(fig)
    else:
        _save_fallback_plot(plot_dir / "fig_trust_separation.pdf", "Trust Separation")

    # PMFA resistance
    if 'pmfa_success_rate_with_ver' in summary_df.columns and 'pmfa_success_rate_no_ver' in summary_df.columns:
        means = [
            summary_df['pmfa_success_rate_no_ver'].mean(),
            summary_df['pmfa_success_rate_with_ver'].mean(),
        ]
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(['No Verification', 'With Verification'], means, color=['tab:red', 'tab:green'])
        ax.set_ylim(0, 1)
        ax.set_ylabel('PMFA success rate')
        ax.set_title('PMFA Resistance')
        fig.tight_layout()
        fig.savefig(plot_dir / "fig_pmfa_resistance.pdf", dpi=160)
        plt.close(fig)
    else:
        _save_fallback_plot(plot_dir / "fig_pmfa_resistance.pdf", "PMFA Resistance")


def run_scenarios(
    config: Dict[str, Any],
    suite: str,
    config_path: Union[str, Path] = "<inline>",
    verbose: bool = False,
    overwrite: bool = False,
    manifest_keep_last: Optional[int] = None,
) -> None:
    _validate_reproducibility_requirements(config, suite)
    base_config_path = Path(config.get("base_config", "config.yaml"))
    config_path_resolved = Path(config_path)
    if not base_config_path.is_absolute() and not base_config_path.exists():
        alt = config_path_resolved.parent / base_config_path
        if alt.exists():
            base_config_path = alt
    base_config = _load_yaml(base_config_path)
    if verbose:
        base_config.setdefault("logging", {})
        base_config["logging"]["level"] = "INFO"
        base_config["logging"]["progress_bar"] = True
    base_config.setdefault("output", {})
    base_config["output"]["overwrite"] = bool(overwrite)
    if manifest_keep_last is not None:
        base_config["output"]["manifest_keep_last"] = int(manifest_keep_last)

    output_root = _suite_output_root(suite)
    config_output = Path(config.get("output_dir", output_root))
    if config_output != output_root:
        LOGGER.warning("Overriding output_dir=%s with canonical %s", config_output, output_root)
    seed_plan = _build_seed_plan(config)
    _write_seed_manifest(output_root, suite, config_path, seed_plan)

    configs_dir = output_root / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)

    seed_for_stats = int(seed_plan[0]["seed"]) if seed_plan else int(config.get("seed_start", 0))
    agg = ExperimentAggregator(
        output_dir=output_root,
        bootstrap_samples=int(config.get("bootstrap_samples", 10000)),
        confidence=float(config.get("confidence", 0.95)),
        alpha_thresholds=config.get("alpha_thresholds"),
        seed=seed_for_stats,
        gate_config=config.get("stats_gate"),
    )

    scenarios = config.get("scenarios", [])
    if not scenarios:
        raise ValueError("Configuration must include at least one scenario entry")
    batch_uid = _make_batch_uid()

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id")
        if not scenario_id:
            raise ValueError("scenario_id is required for each scenario")

        parameter_grid = scenario.get("parameters", {})
        runs_per_variant = int(scenario.get("runs_per_variant", config.get("runs_per_variant", 1)))

        for variant_index, variant in enumerate(_variant_combinations(parameter_grid)):
            for run_index in range(runs_per_variant):
                seed = _resolve_seed_for_run(
                    config,
                    scenario,
                    variant_index,
                    run_index,
                    runs_per_variant,
                )
                experiment_id = f"{scenario_id}_v{variant_index:02d}_r{run_index:02d}_seed{seed}"
                run_uid = f"{batch_uid}_v{variant_index:02d}_r{run_index:02d}_seed{seed}"
                run_id = f"{experiment_id}__{run_uid}"

                run_config = _apply_variant(
                    base_config,
                    variant,
                    scenario,
                    seed,
                    experiment_id,
                    run_uid,
                )
                run_config.setdefault("output", {})
                run_config["output"]["directory"] = str(Path("results"))
                run_config["output"]["overwrite"] = bool(overwrite)
                if manifest_keep_last is not None:
                    run_config["output"]["manifest_keep_last"] = int(manifest_keep_last)
                run_config.setdefault("simulation", {})
                run_config["simulation"]["suite"] = suite
                run_config.setdefault("provenance", {})
                run_config["provenance"]["cli_command"] = " ".join(sys.argv)
                run_config["provenance"]["experiments_config"] = str(config_path)
                run_config_path = configs_dir / f"{run_id}.yaml"
                with run_config_path.open('w', encoding='utf-8') as handle:
                    yaml.safe_dump(run_config, handle, sort_keys=False)

                LOGGER.info("Running scenario=%s variant=%s seed=%s", scenario_id, variant_index, seed)

                engine = SimulationEngine(config_path=str(run_config_path))
                results = engine.run(iterations=engine.total_iterations)

                run_summary = engine.last_run_summary or {}
                summary_row = run_summary.get('summary')
                run_dir = run_summary.get('output_dir')

                if summary_row is None or run_dir is None:
                    # Fallback: load summary.csv directly from run directory
                    default_dir = Path(engine.output_dir or 'results')
                    try:
                        summary_path = default_dir / 'summary.csv'
                        if not summary_path.exists():
                            summary_path = next(default_dir.rglob('summary.csv'))
                        summary_row = pd.read_csv(summary_path).iloc[0].to_dict()
                        run_dir = str(summary_path.parent)
                    except Exception:
                        LOGGER.error("Unable to retrieve summary for run %s", run_id)
                        continue

                agg.add_run(summary_row, run_dir)

    agg.finalize()
    # Generate suite-level plots (best-effort)
    try:
        summary_df = pd.read_csv(output_root / "experiments.csv")
        _generate_suite_plots(summary_df, output_root)
    except Exception as exc:
        LOGGER.warning("Suite plot generation skipped: %s", exc)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CIDSeeks evaluation orchestrator")
    parser.add_argument(
        "--suite",
        required=True,
        choices=["smoke", "paper_core", "robustness_sensitivity", "scalability_stress"],
        help="Suite name (controls canonical output path)",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to experiment YAML (or basename under configs/experiments/)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing run output directory",
    )
    parser.add_argument(
        "--manifest-keep-last",
        type=int,
        default=None,
        help="Retention policy for run manifests (keep latest N entries)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    config_path = _resolve_experiments_config_path(args.config)
    config = _load_yaml(config_path)
    run_scenarios(
        config,
        args.suite,
        config_path=str(config_path),
        verbose=args.verbose,
        overwrite=args.overwrite,
        manifest_keep_last=args.manifest_keep_last,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
