"""
Sentinel AI — Preprocessing Pipeline Module
Ensures compatible transformations between training and inference,
prevents data leakage, scales numerical features, and serializes preprocessing artifacts.
"""

from typing import Tuple, List, Optional
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib
from pathlib import Path
import logging

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.feature_engineering import extract_features, get_feature_names

logger = logging.getLogger("sentinel.preprocessing")


class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """Custom Scikit-learn transformer wrapping feature engineering logic."""
    def __init__(self):
        self.feature_names_: List[str] = []

    def fit(self, X: pd.DataFrame, y=None):
        self.feature_names_ = get_feature_names()
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        features_df = extract_features(X)
        # Ensure exact columns match
        for col in self.feature_names_:
            if col not in features_df.columns:
                features_df[col] = 0.0
        return features_df[self.feature_names_]


def build_preprocessor_pipeline() -> Pipeline:
    """Builds a complete feature extraction and scaling pipeline."""
    return Pipeline([
        ("feature_extractor", SecurityFeatureExtractor()),
        ("scaler", StandardScaler())
    ])


def save_preprocessor(pipeline: Pipeline, path: Path) -> None:
    """Serializes fitted preprocessing pipeline to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)
    logger.info(f"Preprocessor saved to {path}")


def load_preprocessor(path: Path) -> Optional[Pipeline]:
    """Loads fitted preprocessing pipeline from disk."""
    if not path.exists():
        logger.warning(f"Preprocessor artifact not found at {path}")
        return None
    return joblib.load(path)
