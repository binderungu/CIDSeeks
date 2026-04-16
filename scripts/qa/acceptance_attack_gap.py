"""Acceptance matrix for attack robustness gaps (Full vs ablations).

This script runs a compact multi-seed evaluation for four attack types and
four defense profiles:
  - full
  - no_dmpo
  - no_3lc
  - no_auth

For each attack/profile combination, the script executes multiple seeds and
reports AUROC_final mean + bootstrap CI. It then checks the detection-gap
criterion:
  mean(AUROC_full) >= mean(AUROC_ablation) - tolerance
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import numpy as np
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
for import_path in (ROOT, SRC):
    import_path_str = str(import_path)
    if import_path_str not in sys.path:
        sys.path.insert(0, import_path_str)

from simulation.core.simulation_engine import SimulationEngine


ATTACKS = ("PMFA", "Collusion", "Sybil", "Betrayal")
PROFILES: Dict[str, Dict[str, Any]] = {
    "full": {},
    "no_dmpo": {
        "features": {
            "dmpo_pmfa_guard": False,
            "variants_per_alarm": 1,
            "min_alarm_send_delay": 0.0,
            "max_alarm_send_delay": 0.0,
        },
    },
    "no_3lc": {
        "trust_model": {
            "challenge_rate_tiers": {
                "basic": 0.0,
                "advanced": 0.0,
                "final": 0.0,
            },
            "challenge_min_interval_tiers": {
                "basic": 10_000,
                "advanced": 10_000,
                "final": 10_000,
            },
        },
    },
    "no_auth": {
        "auth": {
            "mode": "off",
        },
    },
}


def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected mapping config at {path}")
    return payload


def _deep_update(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _write_yaml(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)


def _bootstrap_ci(values: Iterable[float], samples: int = 3000, ci: float = 0.95) -> Tuple[float, float]:
    arr = np.asarray([float(v) for v in values if np.isfinite(float(v))], dtype=float)
    if arr.size == 0:
        return float("nan"), float("nan")
    if arr.size == 1:
        return float(arr[0]), float(arr[0])
    rng = np.random.default_rng(20260207)
    means = []
    for _ in range(max(1, samples)):
        draw = rng.choice(arr, size=arr.size, replace=True)
        means.append(float(np.mean(draw)))
    alpha = (1.0 - ci) / 2.0
    return (
        float(np.percentile(means, alpha * 100.0)),
        float(np.percentile(means, (1.0 - alpha) * 100.0)),
    )


def _run_matrix(args: argparse.Namespace) -> Dict[str, Any]:
    base_cfg = _load_yaml(Path(args.base_config))
    work_dir = Path(args.work_dir)
    output_root = Path(args.output_root)
    records: List[Dict[str, Any]] = []

    for attack in ATTACKS:
        for profile, overrides in PROFILES.items():
            for seed in args.seeds:
                cfg = copy.deepcopy(base_cfg)
                cfg.setdefault("simulation", {})
                cfg["simulation"]["suite"] = "acceptance"
                cfg["simulation"]["name"] = f"acceptance_{attack.lower()}_{profile}"
                cfg["simulation"]["total_nodes"] = int(args.nodes)
                cfg["simulation"]["iterations"] = int(args.iterations)
                cfg["simulation"]["malicious_ratio"] = float(args.malicious_ratio)
                cfg["simulation"]["seed"] = int(seed)
                cfg["simulation"]["experiment_id"] = f"{attack.lower()}_{profile}_seed{seed}"
                cfg["simulation"]["run_uid"] = f"acceptance_{seed}"
                cfg.setdefault("attack", {})
                cfg["attack"]["type"] = attack
                cfg.setdefault("auth", {})
                cfg.setdefault("features", {})
                cfg.setdefault("output", {})
                cfg["output"]["directory"] = str(output_root)
                cfg["output"]["overwrite"] = True
                cfg["output"]["plot_enabled"] = False
                cfg["output"]["manifest_keep_last"] = int(args.manifest_keep_last)
                cfg.setdefault("logging", {})
                cfg["logging"]["level"] = "WARNING"
                cfg["logging"]["file"] = None

                _deep_update(cfg, overrides)

                config_path = work_dir / f"cfg_{attack.lower()}_{profile}_seed{seed}.yaml"
                _write_yaml(config_path, cfg)
                engine = SimulationEngine(config_path=str(config_path))
                engine.run(iterations=engine.total_iterations)

                summary = (engine.last_run_summary or {}).get("summary", {})
                auroc = summary.get("AUROC_final")
                try:
                    auroc_value = float(auroc)
                except Exception:
                    auroc_value = float("nan")
                records.append(
                    {
                        "attack": attack.lower(),
                        "profile": profile,
                        "seed": int(seed),
                        "AUROC_final": auroc_value,
                        "run_dir": engine.output_dir,
                    }
                )

    stats: Dict[str, Dict[str, Dict[str, float]]] = {}
    for attack in {rec["attack"] for rec in records}:
        stats[attack] = {}
        for profile in PROFILES:
            vals = [rec["AUROC_final"] for rec in records if rec["attack"] == attack and rec["profile"] == profile]
            mean = float(np.nanmean(vals)) if vals else float("nan")
            ci_low, ci_high = _bootstrap_ci(vals)
            stats[attack][profile] = {
                "mean": mean,
                "ci_low": ci_low,
                "ci_high": ci_high,
                "n": len(vals),
            }

    checks = []
    for attack, profile_stats in stats.items():
        full_mean = profile_stats["full"]["mean"]
        for profile in ("no_dmpo", "no_3lc", "no_auth"):
            gap = full_mean - profile_stats[profile]["mean"]
            passed = bool(np.isfinite(gap) and gap >= -float(args.tolerance))
            checks.append(
                {
                    "attack": attack,
                    "compare": f"full_vs_{profile}",
                    "gap_mean": float(gap),
                    "passed": passed,
                }
            )

    all_passed = all(item["passed"] for item in checks)
    return {
        "config": {
            "base_config": str(args.base_config),
            "seeds": list(args.seeds),
            "nodes": int(args.nodes),
            "iterations": int(args.iterations),
            "malicious_ratio": float(args.malicious_ratio),
            "tolerance": float(args.tolerance),
        },
        "records": records,
        "stats": stats,
        "checks": checks,
        "passed": all_passed,
    }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Acceptance matrix for attack robustness gaps")
    parser.add_argument("--base-config", default="config.yaml")
    parser.add_argument("--output-root", default="results")
    parser.add_argument("--work-dir", default="results/acceptance/configs")
    parser.add_argument("--manifest-keep-last", type=int, default=200)
    parser.add_argument("--nodes", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=40)
    parser.add_argument("--malicious-ratio", type=float, default=0.2)
    parser.add_argument("--tolerance", type=float, default=0.02)
    parser.add_argument("--seeds", type=int, nargs="+", default=[101, 202, 303])
    parser.add_argument("--report", default="results/acceptance/attack_gap_report.json")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    report = _run_matrix(args)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if report["passed"]:
        logging.info("Acceptance checks passed.")
        return 0
    logging.error("Acceptance checks failed. See %s", report_path)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
