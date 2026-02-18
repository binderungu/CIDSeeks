import math
import warnings

from evaluation.metrics.enhanced_metrics import compute_auprc, compute_auroc


def test_compute_auroc_one_class_returns_nan_without_warning() -> None:
    labels = [0, 0, 0, 0]
    scores = [0.9, 0.8, 0.7, 0.6]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = compute_auroc(labels, scores)

    assert math.isnan(value)
    assert not any("ROC AUC score is not defined" in str(w.message) for w in caught)


def test_compute_auprc_one_class_returns_nan_without_warning() -> None:
    labels = [0, 0, 0, 0]
    scores = [0.9, 0.8, 0.7, 0.6]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = compute_auprc(labels, scores)

    assert math.isnan(value)
    assert not any("No positive class found in y_true" in str(w.message) for w in caught)

