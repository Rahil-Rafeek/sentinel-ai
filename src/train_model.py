"""
Sentinel AI — Machine Learning Model Training & Evaluation Module
Trains and compares baseline classifiers (Random Forest & Logistic Regression),
implements strict train/test separation to prevent data leakage, handles class imbalance,
computes honest evaluation metrics, and persists fitted model pipelines.
"""

from typing import Dict, Any, Tuple, Optional, List
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import joblib
import logging

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import MODELS_DIR, SAMPLE_DATA_DIR
from src.data_loader import load_dataset
from src.preprocessing import build_preprocessor_pipeline
from src.feature_engineering import extract_features, get_feature_names

logger = logging.getLogger("sentinel.train_model")


def train_and_evaluate_models(
    df: pd.DataFrame,
    target_col: str = "label",
    test_size: float = 0.20,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Trains Random Forest and Logistic Regression classifiers on the dataset.
    Returns complete measured evaluation metrics and model objects.
    """
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not found in dataset for supervised training.")

    # 1. Feature Extraction on full raw dataset
    feature_df = extract_features(df)
    feature_cols = get_feature_names()
    X = feature_df[feature_cols].copy()
    y = df[target_col].astype(str).copy()

    classes = sorted(list(y.unique()))
    if len(classes) < 2:
        raise ValueError("At least 2 distinct classes are required for classification.")

    # 2. Stratified Train / Test Split (Prevention of Data Leakage)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    # 3. Fit Preprocessing Pipeline strictly on X_train
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)  # Leak-free transformation

    results: Dict[str, Any] = {
        "dataset_info": {
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "classes": classes,
            "feature_names": feature_cols,
            "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "scaler": scaler,
        "models": {}
    }

    # Model 1: Logistic Regression Baseline
    lr_model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=random_state,
        solver="lbfgs"
    )
    lr_model.fit(X_train_scaled, y_train)
    y_pred_lr = lr_model.predict(X_test_scaled)
    lr_eval = evaluate_classifier(y_test, y_pred_lr, classes)
    results["models"]["Logistic Regression"] = {
        "model": lr_model,
        "metrics": lr_eval,
        "pipeline_package": {
            "model": lr_model,
            "scaler": scaler,
            "feature_names": feature_cols,
            "classes": classes,
            "model_type": "Logistic Regression",
            "metrics": lr_eval
        }
    }

    # Model 2: Random Forest Baseline
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1
    )
    rf_model.fit(X_train_scaled, y_train)
    y_pred_rf = rf_model.predict(X_test_scaled)
    rf_eval = evaluate_classifier(y_test, y_pred_rf, classes)

    # Feature importances for Random Forest
    importances = dict(zip(feature_cols, rf_model.feature_importances_))
    sorted_importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
    rf_eval["feature_importances"] = sorted_importances

    results["models"]["Random Forest"] = {
        "model": rf_model,
        "metrics": rf_eval,
        "pipeline_package": {
            "model": rf_model,
            "scaler": scaler,
            "feature_names": feature_cols,
            "classes": classes,
            "model_type": "Random Forest",
            "metrics": rf_eval
        }
    }

    return results


def evaluate_classifier(y_true, y_pred, classes: List[str]) -> Dict[str, Any]:
    """Computes measured multi-class evaluation metrics."""
    acc = accuracy_score(y_true, y_pred)
    prec_macro = precision_score(y_true, y_pred, average="macro", zero_division=0)
    rec_macro = recall_score(y_true, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    cm = confusion_matrix(y_true, y_pred, labels=classes)
    clf_report = classification_report(y_true, y_pred, labels=classes, output_dict=True, zero_division=0)

    return {
        "accuracy": float(acc),
        "precision_macro": float(prec_macro),
        "recall_macro": float(rec_macro),
        "f1_macro": float(f1_macro),
        "f1_weighted": float(f1_weighted),
        "confusion_matrix": cm.tolist(),
        "classes": classes,
        "classification_report": clf_report
    }


def train_anomaly_detector(df: pd.DataFrame, contamination: float = 0.15) -> Dict[str, Any]:
    """
    Unsupervised Isolation Forest fallback when ground-truth labels are unavailable.
    Clearly designated as an anomaly detection alternative.
    """
    feature_df = extract_features(df)
    feature_cols = get_feature_names()
    X = feature_df[feature_cols].copy()

    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso_forest = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100
    )
    iso_forest.fit(X_scaled)
    preds = iso_forest.predict(X_scaled)  # -1 for anomaly, 1 for normal
    anomaly_scores = iso_forest.score_samples(X_scaled)

    return {
        "model": iso_forest,
        "scaler": scaler,
        "feature_names": feature_cols,
        "anomaly_count": int((preds == -1).sum()),
        "normal_count": int((preds == 1).sum()),
        "anomaly_scores": anomaly_scores.tolist()
    }


def save_trained_pipeline(pipeline_package: Dict[str, Any], filepath: Path) -> None:
    """Saves model pipeline package to disk with joblib."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline_package, filepath)
    logger.info(f"Model artifact successfully saved to {filepath}")


def load_trained_pipeline(filepath: Path) -> Optional[Dict[str, Any]]:
    """Loads model pipeline package from disk."""
    if not filepath.exists():
        return None
    try:
        return joblib.load(filepath)
    except Exception as e:
        logger.error(f"Error loading model artifact from {filepath}: {e}")
        return None


if __name__ == "__main__":
    sample_file = SAMPLE_DATA_DIR / "synthetic_network_logs.csv"
    if sample_file.exists():
        res = load_dataset(sample_file)
        print("Training models on sample synthetic data...")
        results = train_and_evaluate_models(res.df)
        rf_pkg = results["models"]["Random Forest"]["pipeline_package"]
        lr_pkg = results["models"]["Logistic Regression"]["pipeline_package"]

        rf_path = MODELS_DIR / "sentinel_rf_model.joblib"
        lr_path = MODELS_DIR / "sentinel_lr_model.joblib"

        save_trained_pipeline(rf_pkg, rf_path)
        save_trained_pipeline(lr_pkg, lr_path)
        print(f"Saved Random Forest to {rf_path}")
        print(f"Random Forest F1-Macro: {results['models']['Random Forest']['metrics']['f1_macro']:.4f}")
        print(f"Logistic Regression F1-Macro: {results['models']['Logistic Regression']['metrics']['f1_macro']:.4f}")
