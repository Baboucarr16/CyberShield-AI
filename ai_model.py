"""Validated Random Forest loading and inference."""
from functools import lru_cache
import logging
from pathlib import Path

import joblib
import pandas as pd

from model_features import FEATURE_COLUMNS, to_model_row

logger = logging.getLogger(__name__)
MODEL_PATH = Path(__file__).resolve().parent / "model" / "phishing_model.joblib"


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.is_file():
        return None
    try:
        artifact = joblib.load(MODEL_PATH)
        if not isinstance(artifact, dict) or artifact.get("version") != 1:
            raise ValueError("unsupported artifact format")
        if artifact.get("feature_columns") != list(FEATURE_COLUMNS):
            raise ValueError("feature schema mismatch")
        model = artifact.get("model")
        if not callable(getattr(model, "predict_proba", None)):
            raise ValueError("model has no probability output")
        if getattr(model, "n_features_in_", None) != len(FEATURE_COLUMNS):
            raise ValueError("model feature count mismatch")
        classes = list(getattr(model, "classes_", ()))
        if 1 not in classes:
            raise ValueError("model is missing phishing class")
        return model
    except Exception as exc:
        # Keep scanning available with rules, without returning internal paths or
        # deserialization details to the requester.
        logger.warning("Random Forest unavailable (%s); using rule-based detection", type(exc).__name__)
        return None


def predict_url(features):
    """Return class-1 phishing probability, or None when no valid model exists."""
    model = _load_model()
    if model is None:
        return None
    row = pd.DataFrame([to_model_row(features)], columns=FEATURE_COLUMNS)
    probabilities = model.predict_proba(row)[0]
    classes = list(model.classes_)
    probability = float(probabilities[classes.index(1)])
    if not 0.0 <= probability <= 1.0:
        raise ValueError("Model returned an invalid probability")
    return probability
