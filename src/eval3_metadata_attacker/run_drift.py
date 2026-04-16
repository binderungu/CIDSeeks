from __future__ import annotations

from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .features import build_feature_matrix
from .models import model_registry


DRIFT_FACTORS = {
    "none": 1.0,
    "mild": 1.1,
    "moderate": 1.25,
    "severe": 1.5,
}


def run(dataset_csv: str | Path, drift_mode: str = "mild") -> Dict[str, Any]:
    df = pd.read_csv(dataset_csv)
    x, y, _ = build_feature_matrix(df)
    split_idx = max(1, int(0.6 * len(x)))
    x_train, y_train = x[:split_idx], y[:split_idx]
    x_test, y_test = x[split_idx:], y[split_idx:]

    factor = DRIFT_FACTORS.get(str(drift_mode).lower(), 1.1)
    x_test = np.array(x_test, copy=True)
    if x_test.size:
        x_test[:, 0] = x_test[:, 0] * factor  # delay drift
        x_test[:, 1] = x_test[:, 1] * factor  # payload drift

    out: Dict[str, Any] = {"setting": "drift", "mode": drift_mode, "models": {}}
    for name, spec in model_registry().items():
        model = spec.estimator
        model.fit(x_train, y_train)
        probs = model.predict_proba(x_test)[:, 1] if hasattr(model, 'predict_proba') else model.predict(x_test)
        if len(np.unique(y_test)) > 1:
            auc = float(roc_auc_score(y_test, probs))
            pr = float(average_precision_score(y_test, probs))
        else:
            auc = float('nan')
            pr = float('nan')
        out["models"][name] = {"roc_auc": auc, "pr_auc": pr, "n_test": int(len(y_test))}
    return out
