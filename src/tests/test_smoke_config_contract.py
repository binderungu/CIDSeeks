from pathlib import Path

import yaml  # type: ignore[import-untyped]


def test_smoke_suite_config_matches_canonical_contract() -> None:
    cfg_path = Path("configs/experiments/experiments_smoke.yaml")
    assert cfg_path.exists(), f"missing config: {cfg_path}"

    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    scenarios = cfg.get("scenarios", [])
    assert len(scenarios) == 2

    by_id = {item["scenario_id"]: item for item in scenarios}
    assert set(by_id) == {"smoke_benign", "smoke_collusion"}

    benign = by_id["smoke_benign"]
    assert benign["attack_type"] == "None"
    benign_params = benign["parameters"]
    assert benign_params["n_nodes"] == [30]
    assert benign_params["iterations"] == [200]
    assert benign_params["malicious_ratio"] == [0.0]

    collusion = by_id["smoke_collusion"]
    assert collusion["attack_type"] == "Collusion"
    collusion_params = collusion["parameters"]
    assert collusion_params["n_nodes"] == [30]
    assert collusion_params["iterations"] == [200]
    assert collusion_params["fraction_colluders"] == [0.1]
