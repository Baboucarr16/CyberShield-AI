"""Train and save the URL feature classifier using project-relative paths."""
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from model_features import FEATURE_COLUMNS

DATASET = ROOT / "dataset" / "Phishing_Legitimate_full.csv"
MODEL_PATH = ROOT / "model" / "phishing_model.joblib"


def train():
    data = pd.read_csv(DATASET)
    if "CLASS_LABEL" not in data:
        raise ValueError("Dataset must contain CLASS_LABEL")
    missing_columns = set(FEATURE_COLUMNS).difference(data.columns)
    if missing_columns:
        raise ValueError(f"Dataset is missing required features: {sorted(missing_columns)}")
    X = data.loc[:, FEATURE_COLUMNS].fillna(0)
    y = data["CLASS_LABEL"]
    if y.nunique() < 2:
        raise ValueError("Training dataset must contain both classes")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced", n_jobs=-1)
    model.fit(X_train, y_train)
    accuracy = accuracy_score(y_test, model.predict(X_test))
    joblib.dump({"version": 1, "model": model, "feature_columns": list(FEATURE_COLUMNS)}, MODEL_PATH)
    print(f"Model accuracy: {accuracy:.2%}")
    print(f"Model saved to {MODEL_PATH}")
    return accuracy


if __name__ == "__main__":
    train()
