"""
SHAP explainability module for model interpretability.
Provides feature importance and individual prediction explanations.
"""

from __future__ import annotations

import numpy as np
import shap
from typing import Dict, List, Optional

from ml_model import FEATURE_COLS, FlowDetector


class ExplainabilityEngine:
    """SHAP-based explainability for flow predictions."""

    def __init__(self, detector: FlowDetector):
        self.detector = detector
        self.explainer: Optional[shap.TreeExplainer] = None
        self._initialize_explainer()

    def _initialize_explainer(self):
        """Initialize SHAP explainer for the trained model."""
        if self.detector.mode == "supervised" and self.detector.rf_model is not None:
            self.explainer = shap.TreeExplainer(self.detector.rf_model)
            print("[Explainability] SHAP TreeExplainer initialized")
        else:
            print("[Explainability] Model not in supervised mode - SHAP unavailable")

    def explain_prediction(self, flow_dict: Dict) -> Dict:
        """
        Generate SHAP explanation for a single flow prediction.
        
        Returns:
            {
                "prediction": int,
                "probability": float,
                "shap_values": List[float],
                "feature_names": List[str],
                "base_value": float,
                "top_contributors": List[Dict]
            }
        """
        if self.explainer is None:
            return {"error": "SHAP explainer not available"}

        try:
            # Extract features in correct order
            from ml_model import FEATURE_COLS
            feature_values = []
            for col in FEATURE_COLS:
                val = flow_dict.get(col, 0.0)
                # Handle None and inf values
                if val is None or not isinstance(val, (int, float)):
                    val = 0.0
                elif not np.isfinite(val):
                    val = 0.0
                feature_values.append(float(val))
            
            X = np.array(feature_values).reshape(1, -1)
            
            # Scale features
            if self.detector.scaler:
                X_scaled = self.detector.scaler.transform(X)
            else:
                X_scaled = X

            # Get prediction
            prediction = int(self.detector.rf_model.predict(X_scaled)[0])
            proba = self.detector.rf_model.predict_proba(X_scaled)[0]
            probability = float(proba[1] if len(proba) > 1 else proba[0])

            # Compute SHAP values
            shap_values = self.explainer.shap_values(X_scaled)
            
            # For binary classification, shap_values might be a list [class_0, class_1]
            if isinstance(shap_values, list):
                shap_vals = shap_values[1][0]  # Attack class
            else:
                shap_vals = shap_values[0]

            # Get base value (expected value)
            base_value = float(self.explainer.expected_value[1] if isinstance(
                self.explainer.expected_value, (list, np.ndarray)
            ) else self.explainer.expected_value)

            # Sort features by absolute SHAP value
            feature_importance = [
                {
                    "feature": FEATURE_COLS[i],
                    "value": float(X[0][i]),
                    "shap_value": float(shap_vals[i]),
                    "contribution": "increases" if shap_vals[i] > 0 else "decreases"
                }
                for i in range(len(FEATURE_COLS))
            ]
            feature_importance.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

            return {
                "prediction": prediction,
                "probability": probability,
                "shap_values": [float(v) for v in shap_vals],
                "feature_names": FEATURE_COLS,
                "base_value": base_value,
                "top_contributors": feature_importance[:10],
            }
        except Exception as e:
            return {"error": f"SHAP computation failed: {str(e)}"}

    def get_global_feature_importance(self, X_sample: np.ndarray, max_samples: int = 100) -> List[Dict]:
        """
        Compute global feature importance using SHAP values on a sample.
        
        Args:
            X_sample: Sample of flows (MxN array)
            max_samples: Maximum number of samples to use
            
        Returns:
            List of {feature, mean_abs_shap, importance_rank}
        """
        if self.explainer is None:
            return []

        # Limit sample size
        if len(X_sample) > max_samples:
            indices = np.random.choice(len(X_sample), max_samples, replace=False)
            X_sample = X_sample[indices]

        # Scale if needed
        if self.detector.scaler:
            X_sample = self.detector.scaler.transform(X_sample)

        # Compute SHAP values
        shap_values = self.explainer.shap_values(X_sample)
        
        if isinstance(shap_values, list):
            shap_vals = shap_values[1]  # Attack class
        else:
            shap_vals = shap_values

        # Mean absolute SHAP value per feature
        mean_abs_shap = np.abs(shap_vals).mean(axis=0)

        # Build result
        importance = [
            {
                "feature": FEATURE_COLS[i],
                "mean_abs_shap": float(mean_abs_shap[i]),
                "importance_rank": i + 1
            }
            for i in range(len(FEATURE_COLS))
        ]
        importance.sort(key=lambda x: x["mean_abs_shap"], reverse=True)
        
        # Update ranks
        for rank, item in enumerate(importance, 1):
            item["importance_rank"] = rank

        return importance
