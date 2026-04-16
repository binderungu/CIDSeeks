import copy
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from simulation.core.simulation_engine import SimulationEngine


def _base_config() -> dict:
    root = Path(__file__).resolve().parents[2]
    cfg_path = root / "config.yaml"
    with cfg_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise RuntimeError("config.yaml must contain a mapping")
    return payload


def _write_config(tmp_path: Path, payload: dict) -> Path:
    config_path = tmp_path / "config.test.yaml"
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)
    return config_path


def test_engine_fails_if_run_directory_exists_without_overwrite(tmp_path: Path):
    config = copy.deepcopy(_base_config())
    config.setdefault("simulation", {})
    config["simulation"]["suite"] = "tmp_suite"
    config["simulation"]["experiment_id"] = "exp-alpha"
    config["simulation"]["run_uid"] = "run-fixed"
    config.setdefault("output", {})
    config["output"]["directory"] = str(tmp_path)
    config["output"]["overwrite"] = False
    run_dir = tmp_path / "tmp_suite" / "exp-alpha__run-fixed"
    run_dir.mkdir(parents=True, exist_ok=False)

    config_path = _write_config(tmp_path, config)
    with pytest.raises(FileExistsError):
        SimulationEngine(config_path=str(config_path))


def test_engine_overwrite_replaces_existing_run_directory(tmp_path: Path):
    config = copy.deepcopy(_base_config())
    config.setdefault("simulation", {})
    config["simulation"]["suite"] = "tmp_suite"
    config["simulation"]["experiment_id"] = "exp-beta"
    config["simulation"]["run_uid"] = "run-fixed"
    config.setdefault("output", {})
    config["output"]["directory"] = str(tmp_path)
    config["output"]["overwrite"] = True
    run_dir = tmp_path / "tmp_suite" / "exp-beta__run-fixed"
    run_dir.mkdir(parents=True, exist_ok=False)
    stale_file = run_dir / "stale.txt"
    stale_file.write_text("stale", encoding="utf-8")

    config_path = _write_config(tmp_path, config)
    engine = SimulationEngine(config_path=str(config_path))
    output_dir = Path(engine.output_dir)
    assert output_dir.exists()
    assert output_dir == run_dir
    assert not stale_file.exists()
