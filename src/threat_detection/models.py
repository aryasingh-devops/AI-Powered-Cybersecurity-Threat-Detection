"""Training, evaluation, and prediction for the threat detection models."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from threat_detection.simulation import FEATURE_COLUMNS

MODEL_VERSION = 1


def train_models(
    data: pd.DataFrame,
    model_path: str | Path,
    seed: int = 42,
) -> dict[str, object]:
    """Train a supervised classifier and an unsupervised normal-traffic model."""
    features = data.loc[:, FEATURE_COLUMNS]
    labels = data["is_attack"].astype(int)
    if labels.nunique() != 2:
        raise ValueError("Training data must include both benign and attack examples.")

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=seed,
        stratify=labels,
    )

    classifier = RandomForestClassifier(
        n_estimators=180,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    classifier.fit(x_train, y_train)

    normal_training = x_train.loc[y_train == 0]
    anomaly_model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=seed,
        n_jobs=-1,
    )
    anomaly_model.fit(normal_training)

    predicted = classifier.predict(x_test)
    metrics: dict[str, object] = {
        "accuracy": float(accuracy_score(y_test, predicted)),
        "precision": float(precision_score(y_test, predicted, zero_division=0)),
        "recall": float(recall_score(y_test, predicted, zero_division=0)),
        "f1": float(f1_score(y_test, predicted, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, predicted).tolist(),
        "classification_report": classification_report(
            y_test,
            predicted,
            target_names=["benign", "attack"],
            zero_division=0,
            output_dict=True,
        ),
        "test_rows": int(len(y_test)),
    }

    bundle = {
        "version": MODEL_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "classifier": classifier,
        "anomaly_model": anomaly_model,
        "metrics": metrics,
    }
    target = Path(model_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, target)
    return metrics


def load_models(model_path: str | Path) -> dict[str, object]:
    """Load a locally trained model bundle. Only load trusted model files."""
    path = Path(model_path)
    if not path.is_file():
        raise FileNotFoundError(f"Model file not found: {path}. Run the train command first.")
    bundle = joblib.load(path)
    if bundle.get("version") != MODEL_VERSION:
        raise ValueError("Unsupported model bundle version; retrain with this project version.")
    if bundle.get("feature_columns") != list(FEATURE_COLUMNS):
        raise ValueError("Model feature schema does not match this project.")
    return bundle


def score_traffic(
    data: pd.DataFrame,
    bundle: dict[str, object],
) -> pd.DataFrame:
    """Return predictions, anomaly flags, risk scores, and human-readable reasons."""
    features = data.loc[:, FEATURE_COLUMNS]
    classifier = bundle["classifier"]
    anomaly_model = bundle["anomaly_model"]

    probabilities = classifier.predict_proba(features)[:, 1]
    predictions = classifier.predict(features).astype(int)
    anomaly_flags = (anomaly_model.predict(features) == -1).astype(int)
    anomaly_scores = -anomaly_model.score_samples(features)

    results = data.copy()
    results["attack_probability"] = np.round(probabilities, 4)
    results["classifier_prediction"] = predictions
    results["anomaly_flag"] = anomaly_flags
    results["anomaly_score"] = np.round(anomaly_scores, 4)
    results["alert"] = ((predictions == 1) | (anomaly_flags == 1)).astype(int)
    results["severity"] = np.select(
        [
            results["alert"].eq(0),
            results["attack_probability"].ge(0.85),
            results["attack_probability"].ge(0.60),
        ],
        ["none", "high", "medium"],
        default="low",
    )
    results["alert_reason"] = results.apply(_alert_reason, axis=1)
    return results


def _alert_reason(row: pd.Series) -> str:
    if not row["alert"]:
        return "No alert"
    reasons: list[str] = []
    if row["classifier_prediction"]:
        reasons.append(f"classifier probability {row['attack_probability']:.0%}")
    if row["anomaly_flag"]:
        reasons.append("unusual compared with benign training traffic")
    return "; ".join(reasons)
