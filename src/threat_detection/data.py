"""Dataset loading and validation helpers."""

from pathlib import Path

import pandas as pd

from threat_detection.simulation import FEATURE_COLUMNS, LABEL_COLUMNS


def load_dataset(path: str | Path, require_labels: bool = True) -> pd.DataFrame:
    """Load a CSV; labels are optional only for an inference-only dataset."""
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    data = pd.read_csv(csv_path)
    missing = sorted(set(FEATURE_COLUMNS) - set(data.columns))
    if missing:
        raise ValueError(
            "Dataset is missing required feature columns: "
            + ", ".join(missing)
            + ". See docs/dataset-format.md."
        )
    if data.empty:
        raise ValueError("Dataset contains no rows.")

    has_labels = all(column in data.columns for column in LABEL_COLUMNS)
    has_partial_labels = any(column in data.columns for column in LABEL_COLUMNS) and not has_labels
    if has_partial_labels:
        raise ValueError("Provide both label columns (is_attack and attack_type), or neither.")
    if require_labels and not has_labels:
        raise ValueError("Training data must include is_attack and attack_type labels.")

    for column in FEATURE_COLUMNS:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    if has_labels:
        labels = pd.to_numeric(data["is_attack"], errors="coerce")
        if labels.isna().any() or not set(labels.unique()).issubset({0, 1}):
            raise ValueError("is_attack must contain only numeric 0 (benign) or 1 (attack).")
        if require_labels and labels.nunique() != 2:
            raise ValueError("Training data must contain both benign (0) and attack (1) rows.")
        data["is_attack"] = labels.astype(int)
        data["attack_type"] = data["attack_type"].fillna("unknown").astype(str)
    else:
        data["is_attack"] = pd.NA
        data["attack_type"] = "unknown"

    if data[list(FEATURE_COLUMNS)].isna().any().any():
        raise ValueError("Feature columns contain missing or non-numeric values.")
    if not (data[list(FEATURE_COLUMNS)] >= 0).all().all():
        raise ValueError("Feature values must be non-negative.")
    return data
