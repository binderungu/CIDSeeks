from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd


LOGGER = logging.getLogger(__name__)


class RunIndex:
    def __init__(self, results_root: str | Path, runs_root: str | Path) -> None:
        self.results_root = Path(results_root)
        self.runs_root = self._resolve_manifest_root(runs_root)

    def _resolve_manifest_root(self, runs_root: str | Path) -> Path:
        """Resolve manifest directory to canonical location only.

        `runs_root` is retained for backwards-compatible constructor signature,
        but non-canonical values are ignored.
        """
        canonical = self.results_root / "_manifests"
        configured = Path(runs_root)
        if configured.name == "_manifests":
            return configured
        return canonical

    def _infer_path_fields(self, run_dir: Path) -> Tuple[str, str]:
        """Infer scenario/attack from run directory path."""
        try:
            attack = run_dir.parent.name
            scenario = run_dir.parent.parent.name
            return scenario or "default", attack or "Unknown"
        except Exception:
            return "default", "Unknown"

    def _manifest_roots(self) -> List[Path]:
        return [self.runs_root]

    def scan(self) -> Dict[str, Dict[str, List[str]]]:
        """Scan results directory into scenario -> attack -> [run_id]."""
        index: Dict[str, Dict[str, Set[str]]] = {}
        for run in self.scan_runs():
            scenario = str(run.get("scenario") or "default")
            attack = str(run.get("attack") or "Unknown")
            run_id = str(run.get("run_id") or "")
            if not run_id:
                continue
            index.setdefault(scenario, {}).setdefault(attack, set()).add(run_id)

        stable_index: Dict[str, Dict[str, List[str]]] = {}
        for scenario, attack_map in index.items():
            stable_index[scenario] = {}
            for attack, run_ids in attack_map.items():
                stable_index[scenario][attack] = sorted(run_ids)
        return stable_index

    def _iter_manifest_candidates(self) -> List[Path]:
        candidates: List[Path] = []
        for root in self._manifest_roots():
            if not root.exists():
                continue
            root_candidates = sorted(root.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            candidates.extend(root_candidates)
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return candidates

    def _read_manifest_payload(self, manifest_path: Path) -> Optional[Dict[str, Any]]:
        try:
            with manifest_path.open("r", encoding="utf-8") as fp:
                payload = json.load(fp)
            if not isinstance(payload, dict):
                return None
            return payload
        except Exception:
            LOGGER.debug("Failed to parse manifest payload: %s", manifest_path, exc_info=True)
            return None

    def _read_manifest_results_path(self, manifest_path: Path) -> Optional[Path]:
        payload = self._read_manifest_payload(manifest_path)
        if payload is None:
            return None
        result_path = payload.get("results_path")
        if not result_path:
            return None
        candidate = Path(result_path)
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        return candidate

    def _is_manifest_target_valid(self, target: Path) -> bool:
        try:
            target.relative_to(self.results_root.resolve())
        except ValueError:
            return False
        if not target.exists() or not target.is_dir():
            return False
        return (target / "metadata.json").exists()

    def _iter_valid_manifest_targets(self) -> List[Tuple[Path, Path, Dict[str, Any]]]:
        valid: List[Tuple[Path, Path, Dict[str, Any]]] = []
        for manifest in self._iter_manifest_candidates():
            payload = self._read_manifest_payload(manifest)
            if payload is None:
                continue
            target = self._read_manifest_results_path(manifest)
            if target is None:
                continue
            if not self._is_manifest_target_valid(target):
                continue
            valid.append((manifest, target, payload))
        return valid

    def _manifest_target_payloads(self) -> Dict[str, Dict[str, Any]]:
        """Map resolved run path -> manifest payload for valid canonical targets."""
        payload_by_path: Dict[str, Dict[str, Any]] = {}
        for _manifest, target, payload in self._iter_valid_manifest_targets():
            key = str(target.resolve())
            if key not in payload_by_path:
                payload_by_path[key] = payload
        return payload_by_path

    def _resolve_latest_manifest_for_results(self) -> Optional[Path]:
        valid = self._iter_valid_manifest_targets()
        if valid:
            return valid[0][0]
        return None

    def get_last_run_from_manifest(self) -> Optional[Path]:
        """Return latest run manifest under canonical `<results_root>/_manifests/`."""
        return self._resolve_latest_manifest_for_results()

    def get_last_run_results_path(self) -> Optional[Path]:
        """Resolve latest run directory from canonical manifest.

        Returns None when no manifest is available, malformed, or points outside
        `results_root`.
        """
        valid = self._iter_valid_manifest_targets()
        if valid:
            return valid[0][1]
        return None

    def _append_or_update_run(
        self,
        runs_by_path: Dict[str, Dict[str, Any]],
        *,
        run_dir: Path,
        mtime: float,
        summary_row: Optional[Dict[str, Any]] = None,
        metadata_row: Optional[Dict[str, Any]] = None,
    ) -> None:
        run_dir_resolved = run_dir.resolve()
        key = str(run_dir_resolved)
        run_record = runs_by_path.get(key, {})
        scenario_fallback, attack_fallback = self._infer_path_fields(run_dir)

        payload = summary_row or metadata_row or {}
        scenario = payload.get("scenario") or run_record.get("scenario") or scenario_fallback
        method = (
            payload.get("algo")
            or payload.get("method")
            or run_record.get("method")
            or "unknown"
        )
        attack = payload.get("attack") or run_record.get("attack") or attack_fallback
        run_id = payload.get("run_id") or run_record.get("run_id") or run_dir.name

        merged_summary = dict(run_record.get("summary") or {})
        if metadata_row:
            merged_summary.update(metadata_row)
        if summary_row:
            merged_summary.update(summary_row)

        runs_by_path[key] = {
            "scenario": str(scenario),
            "method": str(method),
            "attack": str(attack),
            "run_id": str(run_id),
            "path": run_dir_resolved,
            "summary": merged_summary,
            "mtime": max(float(run_record.get("mtime", 0.0)), mtime),
        }

    def _extract_metadata_summary(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        summary = metadata.get("summary", {}) if isinstance(metadata.get("summary"), dict) else {}
        summary_meta = dict(summary)
        if "run_id" not in summary_meta and metadata.get("run_id"):
            summary_meta["run_id"] = metadata.get("run_id")
        if "attack" not in summary_meta:
            attack_type = metadata.get("attack_type") or metadata.get("attack")
            if attack_type:
                summary_meta["attack"] = attack_type
        return summary_meta

    def scan_runs(self) -> List[Dict[str, Any]]:
        """Return metadata for manifest-backed runs under canonical results root."""
        runs_by_path: Dict[str, Dict[str, Any]] = {}
        valid_payload_by_path = self._manifest_target_payloads()
        if not valid_payload_by_path:
            return []
        if not self.results_root.exists():
            return []

        for summary_path in self.results_root.rglob("summary.csv"):
            try:
                run_dir = summary_path.parent
                run_dir_resolved = run_dir.resolve()
                if str(run_dir_resolved) not in valid_payload_by_path:
                    continue
                summary_df = _read_csv_safe(summary_path)
                summary_row: Dict[str, Any] = summary_df.iloc[0].to_dict() if not summary_df.empty else {}
                self._append_or_update_run(
                    runs_by_path,
                    run_dir=run_dir,
                    mtime=summary_path.stat().st_mtime,
                    summary_row=summary_row,
                )
            except Exception:
                continue

        for metadata_path in self.results_root.rglob("metadata.json"):
            try:
                run_dir = metadata_path.parent
                run_dir_resolved = run_dir.resolve()
                if str(run_dir_resolved) not in valid_payload_by_path:
                    continue
                with metadata_path.open('r', encoding='utf-8') as handle:
                    metadata = json.load(handle)
                summary_meta = self._extract_metadata_summary(metadata)
                self._append_or_update_run(
                    runs_by_path,
                    run_dir=run_dir,
                    mtime=metadata_path.stat().st_mtime,
                    metadata_row=summary_meta,
                )
            except Exception:
                continue

        runs = list(runs_by_path.values())
        runs.sort(key=lambda item: item.get('mtime', 0.0))
        return runs


class RunArtifacts:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.meta: Dict = {}
        self.auc_per_round: pd.DataFrame = pd.DataFrame()
        self.metrics_per_round: pd.DataFrame = pd.DataFrame()
        self.trust_gap_per_round: pd.DataFrame = pd.DataFrame()
        # Compatibility alias used by UI paths expecting legacy naming.
        self.trust_means: pd.DataFrame = pd.DataFrame()
        self.tti_per_node: pd.DataFrame = pd.DataFrame()
        # Compatibility alias used by UI paths expecting legacy naming.
        self.tti: pd.DataFrame = pd.DataFrame()
        self.fp_curve: pd.DataFrame = pd.DataFrame()
        self.overhead: Optional[pd.DataFrame] = None
        self.stability_per_round: pd.DataFrame = pd.DataFrame()
        self.privacy_leakage_seed: Optional[pd.DataFrame] = None

    @classmethod
    def load(cls, path: str | Path) -> "RunArtifacts":
        base = Path(path)
        art = cls(base)
        summary_path = base / "summary.csv"
        metadata_path = base / "metadata.json"
        if summary_path.exists():
            summary_df = _read_csv_safe(summary_path)
            if not summary_df.empty:
                summary = summary_df.iloc[0].to_dict()
                art.meta = {
                    'summary': summary,
                    'attack': summary.get('attack'),
                    'tau_drop': summary.get('trust_threshold', summary.get('tau_drop')),
                }
        elif metadata_path.exists():
            with metadata_path.open("r", encoding="utf-8") as fp:
                metadata = json.load(fp)
            attack = metadata.get("attack_type") or metadata.get("attack")
            art.meta = {
                "summary": {},
                "attack": attack,
                "tau_drop": None,
                "metadata": metadata,
            }

        # Load CSV artifacts (new pipeline names)
        metrics = _read_csv_safe(base / "metrics_per_round.csv")
        if not metrics.empty:
            art.metrics_per_round = metrics
            art.auc_per_round = metrics.rename(columns={'auroc': 'auc_roc'}).copy()
        trust_gap = _read_csv_safe(base / "trust_gap_per_round.csv")
        if not trust_gap.empty:
            art.trust_gap_per_round = trust_gap
            art.trust_means = trust_gap
        tti = _read_csv_safe(base / "tti_per_node.csv")
        if not tti.empty:
            art.tti_per_node = tti
            art.tti = tti
        fp_curve = _read_csv_safe(base / "fp_curve.csv")
        art.fp_curve = fp_curve
        overhead = _read_csv_safe(base / "overhead_per_round.csv")
        art.overhead = overhead if not overhead.empty else None
        stability = _read_csv_safe(base / "stability_per_round.csv")
        if not stability.empty:
            art.stability_per_round = stability
        leak = _read_csv_safe(base / "privacy_leakage_seed.csv")
        art.privacy_leakage_seed = leak if not leak.empty else None
        return art


class AggregateArtifacts:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.summary: Dict = {}
        self.auc_per_round_mean_ci: pd.DataFrame = pd.DataFrame()
        self.tti_summary: pd.DataFrame = pd.DataFrame()
        self.fp_summary: pd.DataFrame = pd.DataFrame()
        self.overhead_summary: pd.DataFrame = pd.DataFrame()
        self.privacy_leakage_summary: pd.DataFrame = pd.DataFrame()
        # Canonical suite-level outputs
        self.aggregate_summary: pd.DataFrame = pd.DataFrame()
        self.experiments: pd.DataFrame = pd.DataFrame()
        self.stats: pd.DataFrame = pd.DataFrame()

    @classmethod
    def load(cls, path: str | Path) -> "AggregateArtifacts":
        base = Path(path)
        agg = cls(base)
        if (base / "summary.json").exists():
            with (base / "summary.json").open("r", encoding="utf-8") as fp:
                agg.summary = json.load(fp)
        agg.auc_per_round_mean_ci = _read_csv_safe(base / "auc_per_round_mean_ci.csv")
        agg.tti_summary = _read_csv_safe(base / "tti_summary.csv")
        agg.fp_summary = _read_csv_safe(base / "fp_summary.csv")
        agg.overhead_summary = _read_csv_safe(base / "overhead_summary.csv")
        agg.privacy_leakage_summary = _read_csv_safe(base / "privacy_leakage_summary.csv")
        agg.aggregate_summary = _read_csv_safe(base / "aggregate_summary.csv")
        agg.experiments = _read_csv_safe(base / "experiments.csv")
        agg.stats = _read_csv_safe(base / "stats.csv")
        return agg


def _read_csv_safe(path: Path) -> pd.DataFrame:
    try:
        if path.exists():
            return pd.read_csv(path)
    except Exception:
        LOGGER.debug("Failed to read csv artifact: %s", path, exc_info=True)
    return pd.DataFrame()
