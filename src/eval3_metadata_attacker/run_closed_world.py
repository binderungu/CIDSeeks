from __future__ import annotations

from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .features import build_feature_matrix
from .models import model_registry


def _safe_auc(y_true, y_score):
    if len(set(list(y_true))) < 2:
        return float('nan')
    return float(roc_auc_score(y_true, y_score))


def run(dataset_csv: str | Path, random_state: int = 42) -> Dict[str, Any]:
    df = pd.read_csv(dataset_csv)
    x, y, _ = build_feature_matrix(df)
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.3, random_state=random_state, stratify=y if len(set(y)) > 1 else None
    )

    out: Dict[str, Any] = {"setting": "closed_world", "models": {}}
    for name, spec in model_registry().items():
        model = spec.estimator
        model.fit(x_train, y_train)
        probs = model.predict_proba(x_test)[:, 1] if hasattr(model, 'predict_proba') else model.predict(x_test)
        pred = (np.asarray(probs) >= 0.5).astype(int)
        out["models"][name] = {
            "accuracy": float(accuracy_score(y_test, pred)),
            "roc_auc": _safe_auc(y_test, probs),
            "pr_auc": float(average_precision_score(y_test, probs)) if len(np.unique(y_test)) > 1 else float('nan'),
            "n_train": int(len(y_train)),
            "n_test": int(len(y_test)),
        }
    return out
