import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Any
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
)
from backend.app.core.config import settings

def train_or_evaluate_ml(
    df: pd.DataFrame,
    mapping: dict[str, str | None],
    dataset_id: str
) -> dict[str, Any]:
    """
    Execute appropriate machine-learning pipeline based on dataset schema:
    1. If a valid label column exists -> Supervised Random Forest & Logistic Regression with train/test validation
    2. If no labels exist -> Unsupervised Isolation Forest for statistical anomaly profiling
    """
    label_col = mapping.get("label")

    # Select numerical features available in dataset
    numeric_cols = []
    for target_key in ["packet_count", "byte_count", "duration", "login_failures", "src_port", "dst_port"]:
        src_col = mapping.get(target_key)
        if src_col and src_col in df.columns:
            # Check if column is numeric or can be cast
            converted = pd.to_numeric(df[src_col], errors="coerce")
            if converted.notna().sum() > len(df) * 0.3:
                numeric_cols.append(src_col)

    # Fallback to general numeric columns if mapping has few numeric fields
    if len(numeric_cols) < 2:
        for col in df.select_dtypes(include=[np.number]).columns:
            if col != label_col and col not in numeric_cols:
                numeric_cols.append(col)

    if len(numeric_cols) < 1:
        return {
            "is_available": False,
            "is_supervised": False,
            "model_name": "None",
            "notes": "Insufficient numerical features in dataset to fit machine learning models."
        }

    # Extract feature matrix X
    X = df[numeric_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

    # --- Case 1: Supervised ML (Labels exist) ---
    if label_col and label_col in df.columns:
        y_raw = df[label_col].astype(str).str.strip()
        unique_labels = y_raw.unique()

        if len(unique_labels) >= 2 and len(df) >= 20:
            # Map benign vs attack or multiclass
            # Check if binary or multi
            is_binary = len(unique_labels) == 2
            
            # Simple label encoding
            label_map = {lbl: idx for idx, lbl in enumerate(unique_labels)}
            y = y_raw.map(label_map).values

            # Train / test split (80/20) with stratification if feasible
            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42, stratify=y
                )
            except Exception:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42
                )

            # Preprocessing: StandardScaler fitted ONLY on training split
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            # Fit Random Forest
            rf = RandomForestClassifier(n_estimators=100, max_depth=14, random_state=42)
            rf.fit(X_train_scaled, y_train)
            y_pred = rf.predict(X_test_scaled)
            y_proba = rf.predict_proba(X_test_scaled)

            # Compute metrics
            acc = float(accuracy_score(y_test, y_pred))
            prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
            rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
            f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

            roc_auc = None
            try:
                if is_binary:
                    roc_auc = float(roc_auc_score(y_test, y_proba[:, 1]))
                else:
                    roc_auc = float(roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted"))
            except Exception:
                roc_auc = None

            conf_mat = confusion_matrix(y_test, y_pred).tolist()

            # Save model artifact safely in data/models
            model_artifact_path = settings.MODELS_DIR / f"model_{dataset_id}_rf.joblib"
            scaler_artifact_path = settings.MODELS_DIR / f"scaler_{dataset_id}.joblib"
            joblib.dump(rf, model_artifact_path)
            joblib.dump(scaler, scaler_artifact_path)

            return {
                "is_available": True,
                "is_supervised": True,
                "model_name": "Random Forest Classifier (Ensemble of 100 Trees)",
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
                "confusion_matrix": conf_mat,
                "class_labels": [str(l) for l in unique_labels],
                "feature_names": numeric_cols,
                "notes": f"Trained on {len(X_train)} samples, evaluated on {len(X_test)} unseen test samples without data leakage."
            }

    # --- Case 2: Unsupervised Anomaly Detection (Isolation Forest) ---
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso.fit(X_scaled)
    preds = iso.predict(X_scaled)  # -1 = anomaly, 1 = normal
    scores = iso.decision_function(X_scaled)

    anomaly_count = int((preds == -1).sum())
    anomaly_ratio = float(anomaly_count / len(preds))

    return {
        "is_available": True,
        "is_supervised": False,
        "model_name": "Isolation Forest (Unsupervised Anomaly Detector)",
        "anomaly_count": anomaly_count,
        "anomaly_ratio": round(anomaly_ratio, 4),
        "feature_names": numeric_cols,
        "notes": (
            f"Unsupervised statistical outlier analysis identified {anomaly_count} anomalous points "
            f"({anomaly_ratio*100:.1f}% contamination) across {len(numeric_cols)} numeric features. "
            "These represent mathematical deviations and are NOT claimed as confirmed cyberattacks."
        )
    }
