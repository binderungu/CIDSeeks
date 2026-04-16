from __future__ import annotations

from typing import Iterable, Tuple

import numpy as np
import pandas as pd


NUMERIC_COLUMNS = [
    "delay_ms",
    "delay_window_ms",
    "payload_size",
    "K_t",
    "f_t",
    "r_t",
    "cover_fraction",
    "burst_count",
    "burst_mean",
]


def build_feature_matrix(df: pd.DataFrame, target_col: str = "attack_label") -> Tuple[np.ndarray, np.ndarray, list[str]]:
    work = df.copy()
    for col in NUMERIC_COLUMNS:
        if col not in work.columns:
            work[col] = 0.0
    work[NUMERIC_COLUMNS] = work[NUMERIC_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y = pd.to_numeric(work.get(target_col, pd.Series([0] * len(work))), errors="coerce").fillna(0).astype(int)
    x = work[NUMERIC_COLUMNS].to_numpy(dtype=float)
    return x, y.to_numpy(), list(NUMERIC_COLUMNS)


def bootstrap_mean_ci(values: Iterable[float]) -> dict:
    arr = np.array(list(values), dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return {"mean": float("nan"), "ci_low": float("nan"), "ci_high": float("nan")}
    mean = float(arr.mean())
    ci_low = float(np.percentile(arr, 2.5))
    ci_high = float(np.percentile(arr, 97.5))
    return {"mean": mean, "ci_low": ci_low, "ci_high": ci_high}
