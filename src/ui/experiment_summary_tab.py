import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import numpy as np
import logging
from tkinter import filedialog
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from pandas.errors import EmptyDataError

from ui.services.experiment_store import RunIndex, RunArtifacts, AggregateArtifacts
from ui.components.metrics_cards import render_kpi_cards
from ui.components.charts import (
    plot_auc_round,
    plot_trust_gap,
    plot_tti,
    plot_fp_curve,
    plot_overhead,
    plot_leakage,
    plot_stability,
    plot_pmfa_success,
)

# Use a non-interactive backend to avoid display issues
matplotlib.use("Agg")


class ExperimentSummaryTab(ttk.Frame):
    """Experiment Summary – file-based artifacts (no DB dependency)."""

    def __init__(self, parent, cfg: Dict[str, Any] | None = None):
        super().__init__(parent)
        self.logger = logging.getLogger(self.__class__.__name__)
        cfg = cfg or {}
        self.results_dir = cfg.get("results_dir", "results")
        self.runs_dir = cfg.get("runs_dir", "results/_manifests")
        self.default_view = cfg.get("default_view", "scorecard")
        self.auto_refresh_secs = int(cfg.get("auto_refresh_secs", 0) or 0)

        self.available_views = [
            "overview",
            "scorecard",
            "auroc_vs_time",
            "ttd_cdf",
            "trust_gap",
            "overhead_timeseries",
            "stability_kendall",
            "pmfa_success",
            "leakage_auc",
            "fp_fn_curve",
            "significance_tests",
            "scaling_curve",
        ]
        if self.default_view not in self.available_views:
            self.default_view = "scorecard"

        # Index & cache
        self.index = RunIndex(self.results_dir, self.runs_dir)
        self._artifacts_cache: Dict[Any, RunArtifacts | AggregateArtifacts] = {}
        self._current_artifacts: RunArtifacts | AggregateArtifacts | None = None
        self._current_run_path: Optional[Path] = None
        self._stats_cache: Dict[str, pd.DataFrame] = {}
        self._experiments_cache: Dict[str, pd.DataFrame] = {}

        # Figure/canvas
        self.fig = plt.Figure(figsize=(10, 6), facecolor='white')
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas_widget = self.canvas.get_tk_widget()

        # Selectors
        self.scenario_var = tk.StringVar(value="")
        self.method_var = tk.StringVar(value="")
        self.attack_var = tk.StringVar(value="")
        self.run_var = tk.StringVar(value="")
        self.aggregate_var = tk.BooleanVar(value=False)
        self.view_var = tk.StringVar(value=self.default_view)

        # Info
        self.info_label = ttk.Label(self, text="", foreground="blue")

        # Internal caches
        self._runs_by_scenario: Dict[str, Dict[str, Dict[str, List[Dict[str, Any]]]]] = {}
        self._run_lookup: Dict[Tuple[str, str, str, str], Path] = {}
        self._updating_selectors = False

        # Build UI, bind events, load index
        self._init_ui()
        self._bind_events()
        self._load_index()
        if self.auto_refresh_secs > 0:
            self.after(self.auto_refresh_secs * 1000, self._auto_refresh_tick)

    def _init_ui(self) -> None:
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Controls
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(side="top", fill="x", pady=(0, 6))
        controls_frame.columnconfigure(0, weight=1)

        selectors_frame = ttk.Frame(controls_frame)
        selectors_frame.grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.scenario_combo = self._create_selector(selectors_frame, "Scenario", self.scenario_var, width=18)
        self.method_combo = self._create_selector(selectors_frame, "Method", self.method_var, width=18)
        self.attack_combo = self._create_selector(selectors_frame, "Attack", self.attack_var, width=16)
        self.run_combo = self._create_selector(selectors_frame, "Run", self.run_var, width=24)

        actions_frame = ttk.Frame(controls_frame)
        actions_frame.grid(row=0, column=1, sticky="e")

        self.aggregate_check = ttk.Checkbutton(actions_frame, text="Aggregate", variable=self.aggregate_var, state='disabled')
        self.aggregate_check.grid(row=0, column=0, padx=(0, 8))

        ttk.Label(actions_frame, text="View:").grid(row=0, column=1, sticky="w")
        self.view_combo = ttk.Combobox(
            actions_frame,
            textvariable=self.view_var,
            values=self.available_views,
            state="readonly",
            width=20,
        )
        self.view_combo.grid(row=0, column=2, padx=(4, 8))
        self.view_combo.bind("<<ComboboxSelected>>", lambda *_: self._render_current_view())

        refresh_button = ttk.Button(actions_frame, text="Refresh", command=self.refresh_analysis)
        refresh_button.grid(row=0, column=3, padx=(0, 8))

        export_button = ttk.Button(actions_frame, text="Export Plot", command=self._export_pdf)
        export_button.grid(row=0, column=4, padx=(0, 6))
        export_data_button = ttk.Button(actions_frame, text="Export Data", command=self._export_data)
        export_data_button.grid(row=0, column=5)

        # KPI area
        self.kpi_frame = ttk.Frame(main_frame)
        self.kpi_frame.pack(side="top", fill="x", pady=4)

        # Plot area
        self.canvas_widget.pack(side="top", fill="both", expand=True, padx=5, pady=5)

        # Info label
        self.info_label = ttk.Label(main_frame, text="", wraplength=800, justify="center")
        self.info_label.pack(side="bottom", pady=5)

    def _create_selector(self, parent: ttk.Frame, label: str, variable: tk.StringVar, *, width: int = 18) -> ttk.Combobox:
        container = ttk.Frame(parent)
        container.pack(side="left", padx=4)

        ttk.Label(container, text=label).pack(anchor="w")
        combo = ttk.Combobox(container, textvariable=variable, state="disabled", width=width)
        combo.pack(anchor="w", fill="x")
        combo.bind("<<ComboboxSelected>>", self._on_selector_event)
        return combo

    def _on_selector_event(self, *_args) -> None:
        if not self._updating_selectors:
            self._on_selector_change()

    def _set_combobox_items(self, combo: ttk.Combobox, values: List[str], variable: tk.StringVar) -> None:
        combo['values'] = values
        if not values:
            combo.configure(state='disabled')
            if variable.get():
                variable.set("")
            return

        combo.configure(state='readonly')
        current = variable.get()
        if current not in values:
            variable.set(values[-1])

    def _bind_events(self) -> None:
        self.scenario_var.trace_add('write', lambda *_: self._on_selector_change())
        self.method_var.trace_add('write', lambda *_: self._on_selector_change())
        self.attack_var.trace_add('write', lambda *_: self._on_selector_change())
        self.run_var.trace_add('write', lambda *_: self._on_selector_change())
        self.aggregate_var.trace_add('write', lambda *_: self._on_selector_change())

    def refresh_analysis(self, *_args):
        self._load_artifacts()
        self._render_current_view()

    def refresh_from_manifest(self) -> None:
        """Reload run index using the latest manifest selection."""
        self._load_index()

    def _auto_refresh_tick(self):
        try:
            self._load_artifacts()
            self._render_current_view()
        finally:
            if self.auto_refresh_secs > 0:
                self.after(self.auto_refresh_secs * 1000, self._auto_refresh_tick)

    # --- Data access ---
    def _load_index(self) -> None:
        runs = self.index.scan_runs()
        self._runs_by_scenario.clear()
        self._run_lookup.clear()

        for run in runs:
            scenario = run.get('scenario', 'default')
            method = run.get('method', 'unknown')
            attack = run.get('attack', 'Unknown')
            run_id = run.get('run_id')
            path = Path(run.get('path'))
            self._runs_by_scenario.setdefault(scenario, {}).setdefault(method, {}).setdefault(attack, []).append(run)
            self._run_lookup[(scenario, method, attack, run_id)] = path

        # Ensure runs are sorted by timestamp within each bucket
        for scenario_data in self._runs_by_scenario.values():
            for method_data in scenario_data.values():
                for attack, run_list in method_data.items():
                    run_list.sort(key=lambda item: item.get('mtime', 0.0))

        # Preselect latest run from manifest if available
        preselected = False
        try:
            target = self.index.get_last_run_results_path()
            if target:
                resolved_target = target.resolve()
                for (scenario, method, attack, run_id), path in self._run_lookup.items():
                    if path.resolve() == resolved_target:
                        self.scenario_var.set(scenario)
                        self.method_var.set(method)
                        self.attack_var.set(attack)
                        self.run_var.set(run_id)
                        preselected = True
                        break
        except Exception:
            preselected = False

        scenarios = sorted(self._runs_by_scenario.keys())
        self._set_combobox_items(self.scenario_combo, scenarios, self.scenario_var)
        has_runs = bool(self._run_lookup)
        self.aggregate_check.configure(state='normal' if has_runs else 'disabled')
        if not has_runs:
            self.aggregate_var.set(False)

        if scenarios and not preselected:
            self.scenario_var.set(scenarios[-1])

        self._on_selector_change()

    def select_results_path(self, results_path: str) -> None:
        """Force-select a results path and refresh the view."""
        try:
            target = Path(results_path).resolve()
            for (scenario, method, attack, run_id), path in self._run_lookup.items():
                if path.resolve() == target:
                    self.scenario_var.set(scenario)
                    self.method_var.set(method)
                    self.attack_var.set(attack)
                    self.run_var.set(run_id)
                    self._on_selector_change()
                    return
        except Exception:
            return

    def _on_selector_change(self) -> None:
        if self._updating_selectors:
            return

        self._updating_selectors = True
        try:
            scenario = self.scenario_var.get()
            scenario_data = self._runs_by_scenario.get(scenario, {})

            methods = sorted(scenario_data.keys())
            self._set_combobox_items(self.method_combo, methods, self.method_var)

            method = self.method_var.get()
            method_data = scenario_data.get(method, {}) if method else {}

            attacks = sorted(method_data.keys())
            self._set_combobox_items(self.attack_combo, attacks, self.attack_var)

            attack = self.attack_var.get()
            run_options = method_data.get(attack, []) if attack else []
            run_ids = [str(r['run_id']) for r in run_options]
            self._set_combobox_items(self.run_combo, run_ids, self.run_var)

            self._load_artifacts()
            self._render_current_view()
        finally:
            self._updating_selectors = False

    def _load_artifacts(self) -> None:
        scenario = self.scenario_var.get()
        method = self.method_var.get()
        attack = self.attack_var.get()
        run_id = self.run_var.get()
        if not (scenario and method and attack and run_id):
            self._current_artifacts = None
            return

        lookup_key = (scenario, method, attack, run_id)
        run_path = self._run_lookup.get(lookup_key)
        if not run_path:
            self._current_artifacts = None
            return

        self._current_run_path = Path(run_path)

        if self.aggregate_var.get():
            suite_path = self._current_run_path.parent
            cache_key = ('aggregate', suite_path)
            if cache_key not in self._artifacts_cache:
                self._artifacts_cache[cache_key] = AggregateArtifacts.load(suite_path)
            self._current_artifacts = self._artifacts_cache[cache_key]
            return

        cache_key = ('run', self._current_run_path)
        if cache_key not in self._artifacts_cache:
            self._artifacts_cache[cache_key] = RunArtifacts.load(self._current_run_path)
        self._current_artifacts = self._artifacts_cache[cache_key]

    # --- External dataset helpers ---
    def _read_csv_optional(self, path: Path) -> pd.DataFrame:
        if not path.exists():
            return pd.DataFrame()
        try:
            df = pd.read_csv(path)
            return df
        except EmptyDataError:
            return pd.DataFrame()
        except Exception as exc:
            self.logger.error(f"Failed to read CSV at {path}: {exc}")
            return pd.DataFrame()

    def _candidate_paths(self, scenario: str, filename: str) -> List[Path]:
        paths: List[Path] = []
        scenario_path = Path(self.results_dir) / scenario
        if scenario_path.exists():
            paths.append(scenario_path / filename)
        if self._current_run_path is not None:
            paths.append(self._current_run_path.parent.parent / filename)
        root_candidate = Path(self.results_dir) / filename
        if root_candidate not in paths:
            paths.append(root_candidate)
        return paths

    def _get_stats_dataframe(self, scenario: str) -> pd.DataFrame:
        if not scenario:
            return pd.DataFrame()
        if scenario in self._stats_cache:
            return self._stats_cache[scenario]
        for candidate in self._candidate_paths(scenario, 'stats.csv'):
            df = self._read_csv_optional(candidate)
            if not df.empty:
                self._stats_cache[scenario] = df
                return df
        self._stats_cache[scenario] = pd.DataFrame()
        return self._stats_cache[scenario]

    def _get_experiments_dataframe(self, scenario: str) -> pd.DataFrame:
        if not scenario:
            return pd.DataFrame()
        if scenario in self._experiments_cache:
            return self._experiments_cache[scenario]
        for candidate in self._candidate_paths(scenario, 'experiments.csv'):
            df = self._read_csv_optional(candidate)
            if not df.empty:
                self._experiments_cache[scenario] = df
                return df
        self._experiments_cache[scenario] = pd.DataFrame()
        return self._experiments_cache[scenario]

    # --- Renderers ---
    def _render_current_view(self) -> None:
        art = self._current_artifacts
        self.ax.clear()
        if art is None:
            self.info_label.configure(text="")
            self.ax.text(0.5, 0.5, "Select scenario/attack/run", ha='center', va='center')
            self.canvas.draw()
            return
        view = self.view_var.get()
        try:
            summary = self._build_summary_context(art)
            info_parts = []
            if summary:
                method = summary.get('algo') or summary.get('method')
                attack = summary.get('attack')
                scenario = summary.get('scenario') or self.scenario_var.get()
                nodes = summary.get('N')
                colluders = summary.get('fraction_colluders')
                sybils = summary.get('fraction_sybils')
                run_id = summary.get('run_id') or self.run_var.get()
                variant = summary.get('variant')
                info_parts.append(f"Scenario: {scenario}")
                if method:
                    info_parts.append(f"Method: {method}")
                if attack:
                    info_parts.append(f"Attack: {attack}")
                if variant:
                    info_parts.append(f"Variant: {variant}")
                if run_id:
                    info_parts.append(f"Run: {run_id}")
                if self.aggregate_var.get():
                    info_parts.append("Scope: Aggregate")
                n_runs = summary.get('n_runs')
                if n_runs is not None:
                    info_parts.append(f"Runs: {n_runs}")
                if nodes is not None:
                    info_parts.append(f"Nodes: {nodes}")
                if colluders is not None:
                    info_parts.append(f"Colluders: {colluders}")
                if sybils is not None:
                    info_parts.append(f"Sybils: {sybils}")
            self.info_label.configure(text=" | ".join(info_parts))

            if view == "overview":
                self._render_overview(art)
            elif view == "scorecard":
                self._render_scorecard(art)
            elif view == "auroc_vs_time":
                df = getattr(art, 'metrics_per_round', getattr(art, 'auc_per_round', pd.DataFrame()))
                plot_auc_round(self.ax, df)
            elif view == "ttd_cdf":
                plot_tti(self.ax, getattr(art, 'tti_per_node', getattr(art, 'tti', pd.DataFrame())))
            elif view == "trust_gap":
                df = getattr(art, 'trust_gap_per_round', getattr(art, 'trust_means', pd.DataFrame()))
                plot_trust_gap(self.ax, df)
            elif view == "overhead_timeseries":
                plot_overhead(self.ax, getattr(art, 'overhead', None))
            elif view == "stability_kendall":
                plot_stability(self.ax, getattr(art, 'stability_per_round', pd.DataFrame()))
            elif view == "pmfa_success":
                plot_pmfa_success(self.ax, summary)
            elif view == "fp_fn_curve":
                tau = summary.get('trust_threshold') or summary.get('tau_drop')
                if tau is None and hasattr(art, 'meta') and isinstance(art.meta, dict):
                    tau = art.meta.get('tau_drop')
                plot_fp_curve(self.ax, getattr(art, 'fp_curve', pd.DataFrame()), tau or 0.5)
            elif view == "leakage_auc":
                atk = (summary.get('attack') or '').upper()
                if atk != 'PMFA':
                    self.ax.text(0.5, 0.5, "Leakage applies to PMFA only.", ha='center', va='center')
                else:
                    plot_leakage(self.ax, getattr(art, 'privacy_leakage_seed', None))
            elif view == "significance_tests":
                self._render_significance_tests(art, summary)
            elif view == "scaling_curve":
                self._render_scaling_curve(art, summary)
            else:
                self.ax.text(0.5, 0.5, f"Unknown view: {view}", ha='center', va='center')
        except Exception as e:
            self.logger.error(f"Error rendering {view}: {e}")
            self.ax.text(0.5, 0.5, f"Error rendering {view}", ha='center', va='center')
        self.canvas.draw()

    @staticmethod
    def _summary_value(summary: Dict[str, Any], *aliases: str) -> Any:
        for key in aliases:
            if key in summary:
                val = summary[key]
                if isinstance(val, float) and not np.isfinite(val):
                    continue
                return val
        return None

    @staticmethod
    def _is_finite(value: Any) -> bool:
        return isinstance(value, (int, float)) and np.isfinite(value)

    def _build_summary_context(self, art: RunArtifacts | AggregateArtifacts | None) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        if art is None:
            return summary

        if isinstance(art, AggregateArtifacts):
            base = getattr(art, 'summary', {}) or {}
            summary.update(dict(base))
            scenario = self.scenario_var.get()
            method = self.method_var.get()
            attack = self.attack_var.get()
            selected_run = self.run_var.get()
            summary.setdefault('scenario', scenario)
            summary.setdefault('algo', method)
            summary.setdefault('method', method)
            summary.setdefault('attack', attack)
            summary.setdefault('run_id', 'aggregate')
            summary.setdefault('suite', art.base.name)

            experiments_df = getattr(art, 'experiments', pd.DataFrame())
            if not experiments_df.empty:
                filtered = experiments_df.copy()

                if scenario and 'scenario' in filtered.columns:
                    scoped = filtered[filtered['scenario'] == scenario]
                    if not scoped.empty:
                        filtered = scoped

                method_value = summary.get('algo') or summary.get('method')
                if method_value and 'algo' in filtered.columns:
                    scoped = filtered[filtered['algo'] == method_value]
                    if not scoped.empty:
                        filtered = scoped

                if attack and 'attack' in filtered.columns:
                    scoped = filtered[filtered['attack'] == attack]
                    if not scoped.empty:
                        filtered = scoped

                if selected_run and 'run_id' in filtered.columns:
                    selected_rows = filtered[filtered['run_id'] == selected_run]
                    if not selected_rows.empty and 'variant' in selected_rows.columns:
                        variant = selected_rows.iloc[-1].get('variant')
                        if pd.notna(variant):
                            summary.setdefault('variant', variant)
                            if 'variant' in filtered.columns:
                                variant_rows = filtered[filtered['variant'] == variant]
                                if not variant_rows.empty:
                                    filtered = variant_rows

                if 'variant' in filtered.columns and 'variant' not in summary:
                    variant = filtered.iloc[-1].get('variant')
                    if pd.notna(variant):
                        summary['variant'] = variant

                summary['n_runs'] = int(len(filtered))

                numeric_mean_keys = [
                    'AUROC_final',
                    'AUPRC_final',
                    'precision',
                    'recall',
                    'f1_score',
                    'false_positive_rate',
                    'FPR_h',
                    'FNR_m',
                    'bypass_rate',
                    'asr',
                    'fqr',
                    'fnrq',
                    'TTD_median',
                    'msgs_per_round_mean',
                    'latency_per_round_mean',
                    'stability_kendall_tau',
                    'trust_gap_final',
                    'trust_gap_auc',
                    'pmfa_success_rate_no_ver',
                    'pmfa_success_rate_with_ver',
                    'pmfa_success_rate_baseline_no_privacy',
                    'pmfa_success_rate_legacy_dmpo',
                    'pmfa_success_rate_dmpo_x',
                    'trust_threshold',
                ]
                for key in numeric_mean_keys:
                    if key not in filtered.columns:
                        continue
                    values = pd.to_numeric(filtered[key], errors='coerce').dropna()
                    if values.empty:
                        continue
                    summary.setdefault(key, float(values.mean()))

                if 'TTD_median' in filtered.columns:
                    ttd_values = pd.to_numeric(filtered['TTD_median'], errors='coerce')
                    ttd_values = ttd_values[np.isfinite(ttd_values)]
                    if not ttd_values.empty:
                        q1 = float(np.percentile(ttd_values, 25))
                        q3 = float(np.percentile(ttd_values, 75))
                        summary.setdefault('TTD_q1', q1)
                        summary.setdefault('TTD_q3', q3)
                        summary.setdefault('TTD_iqr', q3 - q1)

            aggregate_table = getattr(art, 'aggregate_summary', pd.DataFrame())
            if not aggregate_table.empty and 'metric' in aggregate_table.columns and 'mean' in aggregate_table.columns:
                scoped = aggregate_table.copy()
                if scenario and 'scenario' in scoped.columns:
                    scenario_rows = scoped[scoped['scenario'] == scenario]
                    if not scenario_rows.empty:
                        scoped = scenario_rows
                method_value = summary.get('algo') or summary.get('method')
                if method_value and 'method' in scoped.columns:
                    method_rows = scoped[scoped['method'] == method_value]
                    if not method_rows.empty:
                        scoped = method_rows
                if summary.get('variant') and 'variant' in scoped.columns:
                    variant_rows = scoped[scoped['variant'] == summary.get('variant')]
                    if not variant_rows.empty:
                        scoped = variant_rows

                metric_map = {
                    'AUROC_final': 'AUROC_final',
                    'AUPRC_final': 'AUPRC_final',
                    'TTD_median': 'TTD_median',
                    'msgs_per_round_mean': 'msgs_per_round_mean',
                    'latency_per_round_mean': 'latency_per_round_mean',
                    'stability_kendall_tau': 'stability_kendall_tau',
                    'trust_gap_final': 'trust_gap_final',
                    'trust_gap_auc': 'trust_gap_auc',
                    'pmfa_success_rate_no_ver': 'pmfa_success_rate_no_ver',
                    'pmfa_success_rate_with_ver': 'pmfa_success_rate_with_ver',
                    'pmfa_success_rate_baseline_no_privacy': 'pmfa_success_rate_baseline_no_privacy',
                    'pmfa_success_rate_legacy_dmpo': 'pmfa_success_rate_legacy_dmpo',
                    'pmfa_success_rate_dmpo_x': 'pmfa_success_rate_dmpo_x',
                    'FPR_h': 'FPR_h',
                    'FNR_m': 'FNR_m',
                }
                for out_key, metric_key in metric_map.items():
                    rows = scoped[scoped['metric'] == metric_key]
                    if rows.empty:
                        continue
                    values = pd.to_numeric(rows['mean'], errors='coerce').dropna()
                    if values.empty:
                        continue
                    summary.setdefault(out_key, float(values.mean()))

                if 'n_seeds' in scoped.columns:
                    seed_values = pd.to_numeric(scoped['n_seeds'], errors='coerce').dropna()
                    if not seed_values.empty:
                        summary.setdefault('n_seeds', int(round(float(seed_values.max()))))
        elif hasattr(art, 'meta') and isinstance(art.meta, dict):
            base = art.meta.get('summary', {}) or {}
            summary.update(dict(base))

        if 'asr' not in summary and 'bypass_rate' in summary:
            summary['asr'] = summary.get('bypass_rate')

        if 'latency_ms_mean' not in summary and 'latency_per_round_mean' in summary:
            summary['latency_ms_mean'] = summary.get('latency_per_round_mean')

        ci_low = summary.get('TTD_CI_low') or summary.get('tti_ci_lower')
        ci_high = summary.get('TTD_CI_high') or summary.get('tti_ci_upper')
        if ci_low is not None and ci_high is not None and self._is_finite(ci_low) and self._is_finite(ci_high):
            try:
                ci_low_num = float(ci_low)
                ci_high_num = float(ci_high)
            except (TypeError, ValueError):
                ci_low_num = None
                ci_high_num = None
            if ci_low_num is not None and ci_high_num is not None:
                summary['TTD_ci_str'] = f"{ci_low_num:.1f}–{ci_high_num:.1f}"

        tti_df: pd.DataFrame | None = None
        if isinstance(art, RunArtifacts):
            tti_df = getattr(art, 'tti_per_node', getattr(art, 'tti', pd.DataFrame()))
        elif isinstance(art, AggregateArtifacts):
            tti_df = getattr(art, 'tti_summary', pd.DataFrame())

        if tti_df is not None and not tti_df.empty:
            column = 'tti' if 'tti' in tti_df.columns else None
            if column:
                df = tti_df.copy()
                if 'is_malicious' in df.columns:
                    df = df[df['is_malicious'] == 1]
                series = pd.to_numeric(df[column], errors='coerce')
                series = series[(series >= 0) & np.isfinite(series)]
                if not series.empty:
                    q1 = float(np.percentile(series, 25))
                    q3 = float(np.percentile(series, 75))
                    summary.setdefault('TTD_q1', q1)
                    summary.setdefault('TTD_q3', q3)
                    summary['TTD_q1_q3_str'] = f"{q1:.1f}–{q3:.1f}"
                    summary.setdefault('TTD_iqr', q3 - q1)

        return summary

    def _render_scorecard(self, art: RunArtifacts | AggregateArtifacts) -> None:
        self.ax.clear()
        self.ax.axis('off')

        summary = self._build_summary_context(art)

        render_kpi_cards(self.kpi_frame, summary)

        rows = [
            ("AUROC Final", self._summary_value(summary, "AUROC_final", "auroc_final", "auc_final")),
            ("AUPR Final", self._summary_value(summary, "AUPRC_final", "aupr_final", "auc_pr_final", "AUPRC_mean")),
            ("Precision", self._summary_value(summary, "precision_final", "precision")),
            ("Recall", self._summary_value(summary, "recall_final", "recall", "detection_rate")),
            ("F1 Score", self._summary_value(summary, "f1_final", "f1_score")),
            ("False Positive Rate", self._summary_value(summary, "false_positive_rate", "fp_final", "FPR_h")),
            ("False Negative Rate", self._summary_value(summary, "fn_final", "FNR_m")),
            ("ASR", self._summary_value(summary, "asr", "bypass_rate")),
            ("FQR", self._summary_value(summary, "fqr")),
            ("FNRQ", self._summary_value(summary, "fnrq")),
            ("TTD Median", self._summary_value(summary, "TTD_median", "tti_median")),
            ("TTD IQR", self._summary_value(summary, "TTD_iqr", "tti_iqr")),
            ("TTD Q1", self._summary_value(summary, "TTD_q1")),
            ("TTD Q3", self._summary_value(summary, "TTD_q3")),
            ("TTD 95% CI", self._summary_value(summary, "TTD_ci_str")),
            ("Messages/Round", self._summary_value(summary, "msgs_per_round_mean", "overhead_mean")),
            ("Latency Mean (ms)", self._summary_value(summary, "latency_ms_mean", "latency_per_round_mean")),
            ("Stability τ", self._summary_value(summary, "stability_kendall_tau")),
            ("Trust Gap Final", self._summary_value(summary, "trust_gap_final", "trust_gap")),
            ("Trust Gap AUC", self._summary_value(summary, "trust_gap_auc")),
            ("PMFA CW Acc (No Ver)", self._summary_value(summary, "pmfa_success_rate_baseline_no_privacy", "pmfa_success_rate_no_ver")),
            ("PMFA CW Acc (With Ver)", self._summary_value(summary, "pmfa_success_rate_legacy_dmpo", "pmfa_success_rate_with_ver")),
            ("PMFA CW Acc (DMPO-X)", self._summary_value(summary, "pmfa_success_rate_dmpo_x")),
            ("PMFA Open Adv (DMPO-X)", self._summary_value(summary, "pmfa_open_adv_dmpo_x")),
            ("PMFA Drift AUC (DMPO-X)", self._summary_value(summary, "pmfa_drift_auc_dmpo_x")),
            ("PMFA Best Model (DMPO-X)", self._summary_value(summary, "pmfa_best_model_dmpo_x")),
        ]

        def fmt(val: Any) -> str:
            try:
                if val is None or (isinstance(val, float) and not np.isfinite(val)):
                    return "–"
                if isinstance(val, (int, float)):
                    if 0 <= val <= 1:
                        return f"{val:.3f}"
                    return f"{val:.2f}"
                return str(val)
            except Exception:
                return "–"

        data = [(label, fmt(value)) for label, value in rows]
        table = self.ax.table(cellText=data, colLabels=["Metric", "Value"], loc="center")
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1.2, 1.2)
        self.fig.tight_layout()

    def _render_overview(self, art: RunArtifacts | AggregateArtifacts) -> None:
        summary = self._build_summary_context(art)
        render_kpi_cards(self.kpi_frame, summary)

        self.fig.clear()
        gs = self.fig.add_gridspec(2, 2, hspace=0.35, wspace=0.25)
        ax_auc = self.fig.add_subplot(gs[0, 0])
        ax_trust = self.fig.add_subplot(gs[0, 1])
        ax_ttd = self.fig.add_subplot(gs[1, 0])
        ax_fp = self.fig.add_subplot(gs[1, 1])

        if isinstance(art, RunArtifacts):
            plot_auc_round(ax_auc, art.auc_per_round)
            plot_trust_gap(ax_trust, getattr(art, 'trust_gap_per_round', getattr(art, 'trust_means', pd.DataFrame())))
            plot_tti(ax_ttd, getattr(art, 'tti_per_node', getattr(art, 'tti', pd.DataFrame())))
            tau = summary.get('trust_threshold') or summary.get('tau_drop') or 0.5
            plot_fp_curve(ax_fp, getattr(art, 'fp_curve', pd.DataFrame()), tau)
        else:
            df_auc = getattr(art, 'auc_per_round_mean_ci', pd.DataFrame())
            if df_auc.empty:
                ax_auc.text(0.5, 0.5, "No AUC aggregate", ha='center', va='center')
            else:
                ax_auc.plot(df_auc['round'], df_auc['mean'], label='AUROC mean')
                if 'lower' in df_auc.columns and 'upper' in df_auc.columns:
                    ax_auc.fill_between(df_auc['round'], df_auc['lower'], df_auc['upper'], color='gray', alpha=0.2)
                ax_auc.set_ylim(0.0, 1.0)
                ax_auc.legend()
            plot_trust_gap(ax_trust, getattr(art, 'trust_gap_per_round', pd.DataFrame()))
            plot_tti(ax_ttd, getattr(art, 'tti_summary', pd.DataFrame()))
            plot_fp_curve(ax_fp, getattr(art, 'fp_summary', pd.DataFrame()), summary.get('trust_threshold', 0.5))

    def _render_significance_tests(self, art: RunArtifacts | AggregateArtifacts, summary: Dict[str, Any]) -> None:
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.axis('off')

        scenario = str(summary.get('scenario') or self.scenario_var.get() or '')
        stats_df = self._get_stats_dataframe(scenario)
        if stats_df.empty:
            ax.text(0.5, 0.5, "No statistical tests available. Run the aggregator to generate stats.csv.",
                    ha='center', va='center')
            self.canvas.draw()
            return

        def _apply_filter(df: pd.DataFrame, column: str, value: Any) -> pd.DataFrame:
            if column not in df.columns or value is None or value == "":
                return df
            subset = df[df[column] == value]
            return subset if not subset.empty else df

        df = stats_df.copy()
        df = _apply_filter(df, 'scenario', scenario)
        df = _apply_filter(df, 'variant', summary.get('variant'))
        df = _apply_filter(df, 'method', summary.get('algo') or summary.get('method'))

        if df.empty:
            ax.text(0.5, 0.5, "No matching rows in stats.csv for the selected configuration.",
                    ha='center', va='center')
            self.canvas.draw()
            return

        column_defs: List[Tuple[str, str]] = [
            ("Metric", 'metric'),
            ("Reference", 'reference_method'),
            ("Method", 'method'),
            ("Wilcoxon p", 'wilcoxon_p'),
            ("Benjamini-Hochberg (FDR)", 'wilcoxon_p_adj'),
            ("Cliff’s δ", 'cliffs_delta'),
        ]
        if 'delong_p' in df.columns:
            column_defs.append(("DeLong p", 'delong_p'))
        if 'delong_p_adj' in df.columns:
            column_defs.append(("DeLong BH (FDR)", 'delong_p_adj'))

        def fmt_value(val: Any, is_p: bool = False) -> str:
            try:
                if val is None or (isinstance(val, float) and not np.isfinite(val)):
                    return "–"
                value = float(val)
            except Exception:
                return str(val)
            if is_p:
                marker = "*" if value < 0.05 else ""
                if value < 1e-4:
                    return f"<1e-4{marker}"
                return f"{value:.3g}{marker}"
            return f"{value:.3f}" if abs(value) < 10 else f"{value:.2f}"

        table_rows: List[List[str]] = []
        for _, row in df.sort_values(['metric', 'method']).iterrows():
            cells: List[str] = []
            for label, key in column_defs:
                is_p = key.endswith('_p') or key.endswith('_p_adj')
                cells.append(fmt_value(row.get(key), is_p=is_p))
            table_rows.append(cells)

        col_labels = [label for label, _ in column_defs]
        table = ax.table(cellText=table_rows, colLabels=col_labels, loc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1.2, 1.2)
        ax.set_title("Statistical Significance (Holm-Bonferroni corrected)")
        ax.text(0.5, 0.02, "* indicates p < 0.05", ha='center', va='bottom', fontsize=9, transform=ax.transAxes)

    def _render_scaling_curve(self, art: RunArtifacts | AggregateArtifacts, summary: Dict[str, Any]) -> None:
        self.fig.clear()
        scenario = str(summary.get('scenario') or self.scenario_var.get() or '')
        experiments_df = self._get_experiments_dataframe(scenario)
        ax_top = self.fig.add_subplot(2, 1, 1)
        ax_bottom = self.fig.add_subplot(2, 1, 2)

        if experiments_df.empty:
            ax_top.axis('off')
            ax_bottom.axis('off')
            ax_top.text(0.5, 0.5, "No experiments.csv found. Run aggregation with multiple N values.",
                        ha='center', va='center')
            self.canvas.draw()
            return

        method = summary.get('algo') or summary.get('method')
        attack = summary.get('attack')

        df = experiments_df.copy()
        if 'scenario' in df.columns:
            df = df[df['scenario'] == scenario] if scenario else df
        if method and 'algo' in df.columns:
            df_method = df[df['algo'] == method]
            if not df_method.empty:
                df = df_method
        if attack and 'attack' in df.columns:
            df_attack = df[df['attack'] == attack]
            if not df_attack.empty:
                df = df_attack

        required_cols = {'N', 'AUROC_final', 'TTD_median', 'msgs_per_round_mean'}
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            ax_top.axis('off')
            ax_bottom.axis('off')
            ax_top.text(0.5, 0.5, f"experiments.csv missing columns: {', '.join(missing)}", ha='center', va='center')
            self.canvas.draw()
            return

        agg_map: Dict[str, str] = {
            'AUROC_final': 'mean',
            'TTD_median': 'mean',
            'msgs_per_round_mean': 'mean',
        }
        if 'latency_per_round_mean' in df.columns:
            agg_map['latency_per_round_mean'] = 'mean'
        if 'cpu_time_ms' in df.columns:
            agg_map['cpu_time_ms'] = 'mean'
        if 'mem_peak_mb' in df.columns:
            agg_map['mem_peak_mb'] = 'mean'

        grouped = df.groupby('N').agg(agg_map).reset_index().sort_values('N')

        if grouped.empty:
            ax_top.axis('off')
            ax_bottom.axis('off')
            ax_top.text(0.5, 0.5, "No data after grouping by node count.", ha='center', va='center')
            self.canvas.draw()
            return

        x_vals = grouped['N'].to_numpy()

        ax_top.plot(x_vals, grouped['AUROC_final'], marker='o', label='AUROC')
        ax_top.set_ylabel('AUROC')
        ax_top.set_ylim(0.0, 1.05)
        ax_top.set_title('Detection Performance vs Network Size')

        ax_top_twin = ax_top.twinx()
        ax_top_twin.plot(x_vals, grouped['TTD_median'], marker='s', color='#ff7f0e', label='TTD median')
        ax_top_twin.set_ylabel('TTD Median (rounds)')

        lines, labels = ax_top.get_legend_handles_labels()
        lines2, labels2 = ax_top_twin.get_legend_handles_labels()
        ax_top.legend(lines + lines2, labels + labels2, loc='upper center')

        ax_bottom.plot(x_vals, grouped['msgs_per_round_mean'], marker='o', label='Messages/Round')
        ax_bottom.set_xlabel('Nodes (N)')
        ax_bottom.set_ylabel('Messages/Round')

        if 'latency_per_round_mean' in grouped.columns:
            ax_bottom_twin = ax_bottom.twinx()
            ax_bottom_twin.plot(x_vals, grouped['latency_per_round_mean'], marker='s', color='#2ca02c', label='Latency (ms)')
            ax_bottom_twin.set_ylabel('Latency (ms)')
            lines_b, labels_b = ax_bottom.get_legend_handles_labels()
            lines_b2, labels_b2 = ax_bottom_twin.get_legend_handles_labels()
            ax_bottom.legend(lines_b + lines_b2, labels_b + labels_b2, loc='upper center')
        else:
            ax_bottom.legend(loc='upper center')

        if 'cpu_time_ms' in grouped.columns or 'mem_peak_mb' in grouped.columns:
            metrics_text = []
            if 'cpu_time_ms' in grouped.columns and grouped['cpu_time_ms'].notna().any():
                metrics_text.append('CPU ms vs N available in experiments.csv')
            if 'mem_peak_mb' in grouped.columns and grouped['mem_peak_mb'].notna().any():
                metrics_text.append('Mem peak vs N available in experiments.csv')
            if metrics_text:
                ax_bottom.text(0.02, 0.05, '\n'.join(metrics_text), transform=ax_bottom.transAxes, fontsize=9,
                               va='bottom', ha='left', alpha=0.7)

        self.fig.tight_layout()
    # --- Export ---
    def _export_pdf(self) -> None:
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
                title="Export to PDF",
            )
            if filename:
                self.fig.savefig(filename)
                messagebox.showinfo("Success", "Plot exported successfully!")
        except Exception as e:
            self.logger.error(f"Error exporting to PDF: {e}")
            messagebox.showerror("Error", f"Failed to export: {e}")

    def _export_data(self) -> None:
        try:
            if self._current_artifacts is None:
                return
            scenario = self.scenario_var.get()
            attack = self.attack_var.get()
            base: Path
            if self.aggregate_var.get():
                base = self._current_run_path.parent if self._current_run_path is not None else Path(self.results_dir)
            else:
                run = self.run_var.get()
                base_candidate = self._current_run_path
                if base_candidate is None:
                    base = Path(self.results_dir) / scenario / attack / run
                else:
                    base = Path(base_candidate)
            if not base.exists():
                messagebox.showwarning("Export", "No artifacts to export")
                return
            filename = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP files", "*.zip")])
            if not filename:
                return
            import zipfile
            with zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED) as zf:
                for p in base.glob("**/*"):
                    if p.is_file():
                        # Store relative to results root
                        zf.write(p, p.relative_to(Path(self.results_dir)))
            messagebox.showinfo("Export", f"Exported artifacts to {filename}")
        except Exception as e:
            self.logger.error(f"Export data failed: {e}")
            messagebox.showerror("Export", f"Failed to export: {e}")
