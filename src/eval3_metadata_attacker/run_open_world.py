from __future__ import annotations

from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split

from .features import build_feature_matrix
from .models import model_registry


def run(dataset_csv: str | Path, threshold: float = 0.5, random_state: int = 42) -> Dict[str, Any]:
    df = pd.read_csv(dataset_csv)
    x, y, _ = build_feature_matrix(df)
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.3, random_state=random_state, stratify=y if len(set(y)) > 1 else None
    )

    out: Dict[str, Any] = {"setting": "open_world", "threshold": threshold, "models": {}}
    for name, spec in model_registry().items():
        model = spec.estimator
        model.fit(x_train, y_train)
        probs = model.predict_proba(x_test)[:, 1] if hasattr(model, 'predict_proba') else model.predict(x_test)
        pred = (np.asarray(probs) >= threshold).astype(int)
        out["models"][name] = {
            "precision": float(precision_score(y_test, pred, zero_division=0)),
            "recall": float(recall_score(y_test, pred, zero_division=0)),
            "attacker_advantage": float(abs(pred.mean() - y_test.mean())),
            "n_test": int(len(y_test)),
        }
    return out
