from __future__ import annotations

import logging
from pathlib import Path

import simulate


def test_resolve_experiments_config_path_uses_existing_path_without_warning(
    tmp_path: Path, caplog
) -> None:
    direct_path = tmp_path / "experiments_smoke.yaml"
    direct_path.write_text("suite: smoke\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="simulate"):
        resolved = simulate._resolve_experiments_config_path(direct_path)

    assert resolved == direct_path
    assert "Deprecated config path resolution" not in caplog.text


def test_resolve_experiments_config_path_fallback_warns(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    canonical_dir = tmp_path / "configs" / "experiments"
    canonical_dir.mkdir(parents=True, exist_ok=True)
    fallback_path = canonical_dir / "experiments_smoke.yaml"
    fallback_path.write_text("suite: smoke\n", encoding="utf-8")

    monkeypatch.setattr(simulate, "EXPERIMENT_CONFIG_DIR", canonical_dir)

    with caplog.at_level(logging.WARNING, logger="simulate"):
        resolved = simulate._resolve_experiments_config_path("experiments_smoke.yaml")

    assert resolved == fallback_path
    assert "Deprecated config path resolution" in caplog.text
