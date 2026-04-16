from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from simulate import run_scenarios


def run(
    *,
    suite: str = "smoke",
    config_path: str = "configs/experiments/experiments_smoke.yaml",
    verbose: bool = False,
    overwrite: bool = False,
    resume: bool = False,
) -> Dict[str, Any]:
    """Run the canonical Eval-2 SimPy pipeline through simulate.py orchestration."""
    resolved = Path(config_path)
    with resolved.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    if not isinstance(config, dict):
        raise ValueError(f"Invalid experiment config root in {resolved}")
    run_scenarios(
        config=config,
        suite=suite,
        config_path=str(resolved),
        verbose=verbose,
        overwrite=overwrite,
        resume=resume,
    )
    return {"evaluation": "eval2_simpy_protocol", "status": "completed", "suite": suite, "config": str(resolved)}
