from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier


@dataclass
class ModelSpec:
    name: str
    estimator: Any


def make_logreg() -> LogisticRegression:
    return LogisticRegression(max_iter=500, solver="liblinear", class_weight="balanced")


def make_tree_model() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=4,
        random_state=42,
    )


def make_temporal_model() -> MLPClassifier:
    # Lightweight temporal proxy using flattened sequence stats.
    return MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=400, solver="lbfgs", random_state=42)


def model_registry() -> Dict[str, ModelSpec]:
    return {
        "logreg": ModelSpec(name="logreg", estimator=make_logreg()),
        "tree": ModelSpec(name="tree", estimator=make_tree_model()),
        "temporal": ModelSpec(name="temporal", estimator=make_temporal_model()),
    }
