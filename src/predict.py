"""
Sentinel AI — Unified Threat Inference Engine
Coordinates the end-to-end pipeline:
Feature Extraction -> Scaler -> ML Classification + Rule Engine + Threat Intel -> Severity Assessment.
Clearly separates ML predictions, rule triggers, and verified threat intelligence.
"""

from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
import numpy as np
import uuid
from pathlib import Path
import logging

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import MODELS_DIR, KNOWN_MALICIOUS_INDICATORS
from src.feature_engineering import extract_features, get_feature_names
from src.detection_rules import RuleEngine, RuleMatch
from src.severity import calculate_severity
from src.train_model import load_trained_pipeline

logger = logging.getLogger("sentinel.predict")


class ThreatInferenceEngine:
    def __init__(self, model_filename: str = "sentinel_rf_model.joblib"):
        self.model_path = MODELS_DIR / model_filename
        self.model_package: Optional[Dict[str, Any]] = load_trained_pipeline(self.model_path)
        self.rule_engine = RuleEngine()
        self.known_iocs = KNOWN_MALICIOUS_INDICATORS

    def reload_model(self, model_filename: str) -> bool:
        """Dynamically reloads model artifact."""
        path = MODELS_DIR / model_filename
        pkg = load_trained_pipeline(path)
        if pkg:
            self.model_path = path
            self.model_package = pkg
            return True
        return False

    def predict_events(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Executes end-to-end detection on a dataframe of network events.
        Produces a rich, explainable cybersecurity telemetry dataset.
        """
        if df.empty:
            return pd.DataFrame()

        n_samples = len(df)
        df_clean = df.copy()

        # 1. Run Rule-Based Engine (Stateful sliding window + stateless heuristics)
        rule_matches = self.rule_engine.analyze_dataset(df_clean)

        # 2. Run Machine Learning Pipeline (if model available)
        ml_predictions = ["Benign"] * n_samples
        ml_confidences = [0.0] * n_samples

        if self.model_package is not None:
            try:
                model = self.model_package["model"]
                scaler = self.model_package["scaler"]
                feature_names = self.model_package["feature_names"]

                feature_df = extract_features(df_clean)
                X = feature_df[feature_names].copy()
                X_scaled = scaler.transform(X)

                preds = model.predict(X_scaled)
                ml_predictions = [str(p) for p in preds]

                if hasattr(model, "predict_proba"):
                    probas = model.predict_proba(X_scaled)
                    max_probs = np.max(probas, axis=1)
                    ml_confidences = [float(p) for p in max_probs]
                else:
                    ml_confidences = [0.85] * n_samples
            except Exception as e:
                logger.error(f"Error during ML inference: {e}. Falling back to Rule Engine.")

        # 3. Hybrid Synthesis & Threat Intelligence Correlation
        results: List[Dict[str, Any]] = []

        for i in range(n_samples):
            row = df_clean.iloc[i]
            row_rules: List[RuleMatch] = rule_matches[i]
            ml_pred = ml_predictions[i]
            ml_conf = ml_confidences[i]

            event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
            src_ip = str(row.get("src_ip", "UNKNOWN"))
            dst_ip = str(row.get("dst_ip", "UNKNOWN"))
            dst_port = int(row.get("dst_port", 0))
            bytes_sent = int(row.get("bytes_sent", 0))
            protocol = str(row.get("protocol", "TCP"))
            timestamp = str(row.get("timestamp_str", row.get("timestamp", "")))
            resource = str(row.get("requested_resource", ""))

            # Decision Logic:
            category = "Benign"
            detection_method = "None"
            confidence = 0.99
            evidence = "Normal baseline network communication."
            recommended_action = "No defensive action required. Event classified as benign traffic."
            is_threat = False

            # Check if any rules matched
            if row_rules:
                # Primary rule match
                primary_rule = row_rules[0]
                category = primary_rule.category
                confidence = primary_rule.confidence
                evidence = primary_rule.evidence
                recommended_action = primary_rule.recommended_action
                is_threat = True

                if ml_pred == category:
                    detection_method = f"Hybrid (ML + Rule: {primary_rule.rule_id})"
                    confidence = min(max(confidence, ml_conf) + 0.05, 0.99)
                elif "Threat Intelligence" in primary_rule.rule_name or "IOC" in primary_rule.evidence:
                    detection_method = "Verified Threat Intelligence"
                else:
                    detection_method = f"Rule-Based Engine ({primary_rule.rule_id})"

            # If no rule matched, check if ML predicted a threat with high confidence
            elif ml_pred != "Benign" and ml_conf >= 0.70:
                category = ml_pred
                confidence = ml_conf
                is_threat = True
                detection_method = f"ML Model ({self.model_package.get('model_type', 'Random Forest')})"
                evidence = (
                    f"Machine learning classifier identified multi-dimensional telemetry anomalies "
                    f"characteristic of '{category}' (model confidence: {confidence:.1%})."
                )
                recommended_action = (
                    f"Examine network flow between {src_ip} and {dst_ip}:{dst_port}. "
                    f"Verify whether application traffic aligns with expected operational profile."
                )

            # Compute Severity & Priority
            severity, priority = calculate_severity(
                threat_category=category,
                confidence=confidence,
                rule_matches_count=len(row_rules),
                dst_port=dst_port,
                bytes_transferred=bytes_sent
            )

            results.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(row.get("src_port", 0)),
                "dst_port": dst_port,
                "protocol": protocol,
                "bytes_sent": bytes_sent,
                "bytes_received": int(row.get("bytes_received", 0)),
                "packets_sent": int(row.get("packets_sent", 0)),
                "packets_received": int(row.get("packets_received", 0)),
                "requested_resource": resource,
                "threat_category": category,
                "is_threat": is_threat,
                "severity": severity,
                "priority": priority,
                "confidence": round(confidence, 3),
                "detection_method": detection_method,
                "evidence": evidence,
                "recommended_action": recommended_action,
                "rules_triggered": len(row_rules)
            })

        out_df = pd.DataFrame(results)
        return out_df
