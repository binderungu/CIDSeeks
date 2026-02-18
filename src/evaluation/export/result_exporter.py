from __future__ import annotations

"""Evaluation-layer result exporter (canonical path)."""

from datetime import datetime
import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping

import numpy as np
import pandas as pd
import yaml


class ResultExporter:
    def __init__(self, results_dir: str = "results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def export_results(
        self,
        results: Dict[str, Any],
        formats: List[str] = ["json", "csv", "excel"],
    ):
        """Export results in specified formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = self.results_dir / f"simulation_results_{timestamp}"

        for fmt in formats:
            if fmt == "json":
                self._export_json(results, base_path)
            elif fmt == "csv":
                self._export_csv(results, base_path)
            elif fmt == "excel":
                self._export_excel(results, base_path)
            elif fmt == "yaml":
                self._export_yaml(results, base_path)

    def _export_json(self, results: Dict, base_path: Path):
        """Export results as JSON."""
        with open(f"{base_path}.json", "w") as f:
            json.dump(results, f, indent=2, default=self._json_serializer)

        metrics_path = base_path.parent / "detailed_metrics"
        metrics_path.mkdir(exist_ok=True)

        for metric_type, data in results["metrics"].items():
            metric_file = metrics_path / f"{metric_type}.json"
            with open(metric_file, "w") as f:
                json.dump(data, f, indent=2, default=self._json_serializer)

    def _export_csv(self, results: Dict, base_path: Path):
        """Export results as CSV files."""
        flat_data = self._flatten_dict(results)

        with open(f"{base_path}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value"])
            for key, value in flat_data.items():
                writer.writerow([key, value])

        if "time_series" in results:
            ts_path = base_path.parent / "time_series"
            ts_path.mkdir(exist_ok=True)

            for metric, series in results["time_series"].items():
                df = pd.DataFrame(series)
                df.to_csv(ts_path / f"{metric}.csv", index=False)

    def _export_excel(self, results: Dict, base_path: Path):
        """Export results as Excel workbook."""
        with pd.ExcelWriter(f"{base_path}.xlsx") as writer:
            overview_data = self._flatten_dict(results["overview"])
            pd.DataFrame(list(overview_data.items()), columns=["Metric", "Value"]).to_excel(
                writer, sheet_name="Overview", index=False
            )

            for metric_type, data in results["metrics"].items():
                if isinstance(data, dict):
                    df = pd.DataFrame(data).reset_index()
                    df.columns = ["Timestamp" if col == "index" else col for col in df.columns]
                else:
                    df = pd.DataFrame({"Value": data}, index=[0])
                df.to_excel(writer, sheet_name=metric_type, index=False)

            if "network_analysis" in results:
                network_df = pd.DataFrame(results["network_analysis"])
                network_df.to_excel(writer, sheet_name="Network_Analysis", index=False)

    def _export_yaml(self, results: Dict, base_path: Path):
        """Export results as YAML."""
        with open(f"{base_path}.yaml", "w") as f:
            yaml.dump(results, f, default_flow_style=False)

    def _flatten_dict(self, d: Dict, parent_key: str = "", sep: str = ".") -> Dict:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def _json_serializer(self, obj):
        """JSON serializer for objects not serializable by default."""
        if isinstance(obj, (np.int64, np.int32)):
            return int(obj)
        if isinstance(obj, (np.float64, np.float32)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    def export_run_artifacts(
        self,
        scenario: str,
        attack: str,
        run_id: str,
        artifacts: Mapping[str, Any],
        meta: Mapping[str, Any],
    ) -> Path:
        """
        Export per-run CSV/JSON artifacts:
          results/<scenario>/<attack>/<run_id>/
            - auc_per_round.csv
            - trust_means.csv
            - tti.csv
            - fp_curve.csv
            - overhead.csv (optional)
            - privacy_leakage_seed.csv (optional)
            - ids_prf_vs_tau.csv (optional)
            - meta.json
        """
        base = self.results_dir / scenario / attack / run_id
        base.mkdir(parents=True, exist_ok=True)

        def _write_csv(name: str, rows: Any) -> None:
            out = base / f"{name}.csv"
            if isinstance(rows, pd.DataFrame):
                rows.to_csv(out, index=False)
                return
            if isinstance(rows, list):
                if not rows:
                    with out.open("w", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([])
                    return
                if isinstance(rows[0], dict):
                    with out.open("w", newline="") as f:
                        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                        writer.writeheader()
                        writer.writerows(rows)
                else:
                    with out.open("w", newline="") as f:
                        writer = csv.writer(f)
                        for r in rows:
                            writer.writerow([r])
            elif isinstance(rows, dict):
                with out.open("w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=list(rows.keys()))
                    writer.writeheader()
                    writer.writerow(rows)
            else:
                with out.open("w") as f:
                    f.write(str(rows))

        mapping = {
            "auc_per_round": "auc_per_round",
            "trust_means": "trust_means",
            "tti": "tti",
            "fp_curve": "fp_curve",
            "overhead": "overhead",
            "privacy_leakage_seed": "privacy_leakage_seed",
            "ids_prf_vs_tau": "ids_prf_vs_tau",
        }
        for key, filename in mapping.items():
            if key in artifacts and artifacts[key] is not None:
                _write_csv(filename, artifacts[key])

        try:
            if "round_metrics" in artifacts and artifacts["round_metrics"] is not None:
                _write_csv("round_metrics", artifacts["round_metrics"])
            if "node_round" in artifacts and artifacts["node_round"] is not None:
                _write_csv("node_round", artifacts["node_round"])
        except Exception:
            self.logger.debug(
                "Failed to export optional round-level artifacts for run_id=%s",
                run_id,
                exc_info=True,
            )

        with (base / "meta.json").open("w", encoding="utf-8") as fp:
            json.dump(dict(meta), fp, indent=2, sort_keys=True, default=self._json_serializer)

        return base
