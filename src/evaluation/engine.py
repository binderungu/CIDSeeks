from __future__ import annotations

"""Light-weight singleton Engine for experiment logging.
This avoids coupling UI & simulation; any script can do:

    from evaluation.engine import Engine
    Engine.current_run.metrics["key"] = value
    Engine.current_run.flush()

UI front-end (JS / Tk) only needs to read Engine.current_run.metrics.
Default manifest path is `results/_manifests/`.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Union, List

_LOGGER = logging.getLogger(__name__)


class _Run:
    """Represents a single experiment session."""

    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self.start_ts: float = datetime.utcnow().timestamp()
        self._dirty = False  # flag if new data added since last flush

    # ------------------------------------------------------------------
    def _prune_old_manifests(self, out_dir: Path, keep_last: Optional[int]) -> None:
        if keep_last is None:
            return
        try:
            limit = int(keep_last)
        except Exception:
            return
        if limit <= 0:
            return
        manifests: List[Path] = sorted(out_dir.glob("run_*.json"))
        excess = len(manifests) - limit
        if excess <= 0:
            return
        for stale in manifests[:excess]:
            try:
                stale.unlink()
            except Exception as exc:
                _LOGGER.debug("Failed to remove stale manifest %s: %s", stale, exc)

    def flush(
        self,
        out_dir: Optional[Union[str, Path]] = None,
        keep_last: Optional[int] = None,
    ) -> None:
        """Persist metrics to a JSON artifact so UI or other tooling can reload.
        If *out_dir* is None, the file is written to
        ./results/_manifests/ with timestamp.
        """
        if not self._dirty:
            return  # nothing new

        out_dir = Path(out_dir) if out_dir else Path("results/_manifests")
        out_dir.mkdir(parents=True, exist_ok=True)

        # Include microseconds to avoid collisions during fast batch runs.
        ts_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        out_file = out_dir / f"run_{ts_str}.json"
        try:
            with out_file.open("w", encoding="utf-8") as fp:
                json.dump(self.metrics, fp, indent=2, sort_keys=True)
            _LOGGER.info("Run metrics flushed to %s", out_file)
            self._prune_old_manifests(out_dir=out_dir, keep_last=keep_last)
        except Exception as exc:
            _LOGGER.error("Failed to flush metrics: %s", exc)
        finally:
            self._dirty = False

    # ------------------------------------------------------------------
    def log_metric(self, key: str, value: Any) -> None:
        self.metrics[key] = value
        self._dirty = True

    def reset(self):
        self.metrics.clear()
        self._dirty = False


class _Engine:
    """Global access point. Only one active _Run at a time."""

    def __init__(self):
        self.current_run: _Run = _Run()

    # Convenience passthroughs ------------------------------------------------
    def log(self, key: str, value: Any) -> None:  # noqa: D401 – simple helper
        self.current_run.log_metric(key, value)

    def flush(
        self,
        out_dir: Optional[Union[str, Path]] = None,
        keep_last: Optional[int] = None,
    ) -> None:
        self.current_run.flush(out_dir, keep_last=keep_last)

    def reset(self):
        self.current_run = _Run()


# Global singleton -----------------------------------------------------------
Engine: _Engine = _Engine() 
