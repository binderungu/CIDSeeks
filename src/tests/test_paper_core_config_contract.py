from pathlib import Path

import yaml  # type: ignore[import-untyped]


def _load_yaml(path: str) -> dict:
    cfg_path = Path(path)
    assert cfg_path.exists(), f"missing config: {cfg_path}"
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_paper_core_ci_gate_uses_canonical_dmpox_and_attribution() -> None:
    cfg = _load_yaml("configs/experiments/experiments_paper_core_ci_gate.yaml")
    scenarios = cfg.get("scenarios", [])
    assert len(scenarios) == 1
    scenario = scenarios[0]
    assert scenario["scenario_id"] == "pmfa_ci_gate"
    params = scenario["parameters"]
    assert params["privacy_strategy"] == ["dmpo_x"]
    assert params["attribution_profile"] == ["full"]
    assert params["auth_mode"] == ["required"]


def test_paper_core_balanced_includes_pmfa_attribution_ablation_and_canonical_profiles() -> None:
    cfg = _load_yaml("configs/experiments/experiments_paper_core_balanced.yaml")
    by_id = {item["scenario_id"]: item for item in cfg.get("scenarios", [])}
    assert "pmfa_balanced" in by_id
    assert "pmfa_attribution_balanced" in by_id

    pmfa_params = by_id["pmfa_balanced"]["parameters"]
    assert pmfa_params["privacy_strategy"] == ["dmpo_legacy", "dmpo_x"]
    assert pmfa_params["attribution_profile"] == ["full"]
    assert pmfa_params["auth_mode"] == ["required"]

    attribution_params = by_id["pmfa_attribution_balanced"]["parameters"]
    assert attribution_params["privacy_strategy"] == ["dmpo_x"]
    assert attribution_params["attribution_profile"] == [
        "full",
        "no_fibd",
        "no_split_fail",
        "no_coalcorr",
    ]

    for scenario_id in ("collusion_balanced", "sybil_balanced", "betrayal_balanced"):
        params = by_id[scenario_id]["parameters"]
        assert params["privacy_strategy"] == ["dmpo_x"]
        assert params["auth_mode"] == ["required"]


def test_robustness_and_scalability_configs_pin_canonical_dmpox() -> None:
    auth_cfg = _load_yaml("configs/experiments/experiments_auth_sensitivity.yaml")
    for scenario in auth_cfg.get("scenarios", []):
        params = scenario["parameters"]
        assert params["privacy_strategy"] == ["dmpo_x"]
        assert params["attribution_profile"] == ["full"]

    scalability_cfg = _load_yaml("configs/experiments/experiments_scalability_stress.yaml")
    scenarios = scalability_cfg.get("scenarios", [])
    assert len(scenarios) == 1
    params = scenarios[0]["parameters"]
    assert params["privacy_strategy"] == ["dmpo_x"]
    assert params["attribution_profile"] == ["full"]
    assert params["auth_mode"] == ["required"]
