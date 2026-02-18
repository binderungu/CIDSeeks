import ast
from pathlib import Path


def test_experiment_summary_tab_has_single_refresh_analysis_definition() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "src" / "ui" / "experiment_summary_tab.py"
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    class_defs = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ExperimentSummaryTab"
    ]
    assert class_defs, "ExperimentSummaryTab class is missing"

    class_def = class_defs[0]
    refresh_defs = [
        node
        for node in class_def.body
        if isinstance(node, ast.FunctionDef) and node.name == "refresh_analysis"
    ]

    assert len(refresh_defs) == 1, (
        "ExperimentSummaryTab.refresh_analysis must be defined exactly once; "
        f"found {len(refresh_defs)} definitions"
    )

    method_names = [
        node.name
        for node in class_def.body
        if isinstance(node, ast.FunctionDef)
    ]
    assert len(method_names) == len(set(method_names)), (
        "ExperimentSummaryTab must not define duplicate methods; "
        "later definitions silently override earlier ones."
    )

    forbidden_legacy_defs = {
        "_auto_refresh",
        "refresh_summary",
        "_refresh_analysis_legacy_db",
        "_do_refresh_background",
        "_process_queue",
        "_get_time_to_detect_data",
        "_plot_time_detect",
        "_get_trust_degradation_data",
        "_plot_trust_degradation",
        "_get_fraction_undetected_data",
        "_plot_fraction_undetected",
        "_get_misalignment_data",
        "_plot_misalignment",
        "_get_cost_overhead_data",
        "_plot_cost_overhead",
        "_build_overview_summary",
        "_plot_overview_chart",
        "_plot_detection_overview",
        "_plot_convergence_overview",
        "_plot_resilience_overview",
        "_plot_efficiency_overview",
        "_build_detection_metric_summary",
        "_plot_detection_metric",
        "_build_convergence_metric_summary",
        "_plot_convergence_metric",
        "_build_resilience_metric_summary",
        "_plot_resilience_metric",
        "_build_efficiency_metric_summary",
        "_plot_efficiency_metric",
        "_build_all_metrics_summary",
        "_plot_all_metrics_comparison",
        "_get_all_methods_data",
        "_get_roc_data_for_method",
        "_get_latency_data_for_method",
        "_plot_roc_curves",
        "_plot_latency_cdf",
        "_plot_metrics_bar_chart",
        "_format_method_name",
        "_calculate_statistical_significance",
        "_add_significance_markers",
        "_export_comparison_data",
    }
    class_method_names = set(method_names)
    unexpected = forbidden_legacy_defs.intersection(class_method_names)
    assert not unexpected, (
        "ExperimentSummaryTab must not reintroduce legacy DB refresh methods; "
        f"found {sorted(unexpected)}"
    )
