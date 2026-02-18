"""Validate stats gate artifact by recomputing checks from aggregate summary."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


REQUIRED_TOP_LEVEL_KEYS = ("suite", "config", "checked_rows", "failures", "passed")


def _load_json_object(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"stats gate file not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid stats gate payload in {path}")
    return payload


def _load_aggregate_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"aggregate summary file not found: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _normalize_gate_config(raw: Any) -> Dict[str, Any]:
    config = raw if isinstance(raw, dict) else {}
    required_metrics = config.get("required_metrics")
    if not isinstance(required_metrics, list) or not required_metrics:
        required_metrics = ["AUROC_final"]
    required_metrics = [str(item) for item in required_metrics if str(item).strip()]
    max_ci_width = config.get("max_ci_width")
    if not isinstance(max_ci_width, dict):
        max_ci_width = {}

    normalized_bounds: Dict[str, float] = {}
    for metric, bound in max_ci_width.items():
        parsed = _coerce_float(bound)
        if parsed is not None and math.isfinite(parsed):
            normalized_bounds[str(metric)] = float(parsed)

    return {
        "min_seeds": _coerce_int(config.get("min_seeds"), default=1),
        "required_metrics": required_metrics,
        "max_ci_width": normalized_bounds,
        "enforce": _coerce_bool(config.get("enforce"), default=True),
    }


def _schema_issues(payload: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    for key in REQUIRED_TOP_LEVEL_KEYS:
        if key not in payload:
            issues.append(f"missing top-level key: {key}")
    failures = payload.get("failures", [])
    if not isinstance(failures, list):
        issues.append("field 'failures' must be a list")
    checked_rows = payload.get("checked_rows")
    if not isinstance(checked_rows, int):
        issues.append("field 'checked_rows' must be an integer")
    passed = payload.get("passed")
    if not isinstance(passed, bool):
        issues.append("field 'passed' must be a boolean")
    return issues


def _recompute_failures(
    rows: Iterable[Dict[str, str]],
    gate_config: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], int]:
    required_metrics = gate_config["required_metrics"]
    required_set = set(required_metrics)
    min_seeds = int(gate_config["min_seeds"])
    max_ci_width = gate_config["max_ci_width"]

    rows_list = list(rows)
    checked_rows = sum(1 for row in rows_list if row.get("metric") in required_set)
    failures: List[Dict[str, Any]] = []

    for metric in required_metrics:
        metric_rows = [row for row in rows_list if row.get("metric") == metric]
        if not metric_rows:
            failures.append(
                {
                    "metric": metric,
                    "reason": "missing_required_metric",
                }
            )
            continue

        for row in metric_rows:
            scenario = row.get("scenario")
            variant = row.get("variant")
            method = row.get("method")
            n_seeds = _coerce_int(row.get("n_seeds"), default=0)
            if n_seeds < min_seeds:
                failures.append(
                    {
                        "metric": metric,
                        "scenario": scenario,
                        "variant": variant,
                        "method": method,
                        "reason": "insufficient_seeds",
                        "observed": n_seeds,
                        "required": min_seeds,
                    }
                )

            ci_bound = max_ci_width.get(metric)
            if ci_bound is None:
                continue
            ci_width = _coerce_float(row.get("ci_width"))
            if ci_width is None or not math.isfinite(ci_width):
                continue
            if float(ci_width) > float(ci_bound):
                failures.append(
                    {
                        "metric": metric,
                        "scenario": scenario,
                        "variant": variant,
                        "method": method,
                        "reason": "ci_too_wide",
                        "observed": float(ci_width),
                        "required": float(ci_bound),
                    }
                )

    return failures, checked_rows


def _normalize_failure_item(item: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key in ("metric", "scenario", "variant", "method", "reason", "observed", "required"):
        value = item.get(key)
        if isinstance(value, float) and math.isfinite(value):
            value = round(value, 12)
        normalized[key] = value
    return normalized


def _failure_signatures(items: Iterable[Dict[str, Any]]) -> List[str]:
    normalized = [_normalize_failure_item(item) for item in items]
    return sorted(json.dumps(item, sort_keys=True) for item in normalized)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check reproducibility/statistics gate output")
    parser.add_argument(
        "--path",
        default="results/paper_core/stats_gate.json",
        help="Path to stats_gate.json",
    )
    parser.add_argument(
        "--allow-suite",
        action="append",
        default=[],
        help="Suite names allowed to skip strict gate failure (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    gate_path = Path(args.path)
    payload = _load_json_object(gate_path)
    issues = _schema_issues(payload)
    if issues:
        print(f"stats gate invalid schema path={args.path}")
        for issue in issues:
            print(f"- {issue}")
        return 1

    gate_config = _normalize_gate_config(payload.get("config"))
    aggregate_path = gate_path.parent / "aggregate_summary.csv"
    aggregate_rows = _load_aggregate_rows(aggregate_path)
    expected_failures, expected_checked_rows = _recompute_failures(aggregate_rows, gate_config)

    consistency_issues: List[str] = []
    observed_checked_rows = _coerce_int(payload.get("checked_rows"), default=-1)
    if observed_checked_rows != expected_checked_rows:
        consistency_issues.append(
            f"checked_rows mismatch (observed={observed_checked_rows}, expected={expected_checked_rows})"
        )

    observed_failures = payload.get("failures", [])
    if _failure_signatures(observed_failures) != _failure_signatures(expected_failures):
        consistency_issues.append("failures payload mismatch against aggregate_summary.csv recomputation")

    observed_passed = bool(payload.get("passed"))
    expected_passed = len(expected_failures) == 0
    if observed_passed != expected_passed:
        consistency_issues.append(
            f"passed mismatch (observed={observed_passed}, expected={expected_passed})"
        )

    if consistency_issues:
        print(f"stats gate consistency check failed path={args.path}")
        for issue in consistency_issues:
            print(f"- {issue}")
        return 1

    suite = str(payload.get("suite") or "")
    if not gate_config["enforce"]:
        print(f"stats gate skipped (enforce=false) for suite={suite} path={args.path}")
        return 0

    if expected_passed:
        print(f"stats gate passed for suite={suite} path={args.path}")
        return 0

    if suite in set(args.allow_suite):
        print(
            f"stats gate failed but allowed for suite={suite}: "
            f"failures={len(expected_failures)} path={args.path}"
        )
        return 0

    print(
        f"stats gate failed for suite={suite}: "
        f"failures={len(expected_failures)} path={args.path}"
    )
    for item in expected_failures[:20]:
        print(json.dumps(item, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
