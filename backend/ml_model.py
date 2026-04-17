"""
ML model – FlowDetector class supporting both supervised and unsupervised modes.

Supervised mode:
  - RandomForestClassifier trained on real CIC-IDS2017 data
  - Undersamples majority class to 1:10 ratio before SMOTE
  - Then SMOTE oversamples minority to 1:1
  - This prevents SMOTE from being overwhelmed by 200k majority samples

Unsupervised mode:
  - IsolationForest for anomaly detection when no labels available
  - Contamination rate 0.1
"""

from __future__ import annotations
import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline

# ---------------------------------------------------------------------------
# Feature columns the model operates on
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    "duration",
    "total_packets",
    "total_bytes",
    "mean_pkt_size",
    "std_pkt_size",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_iat",
    "std_iat",
    "burst_count",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "retransmit_count",
    "avg_window_size",
    "fwd_bwd_ratio",
]

# ---------------------------------------------------------------------------
# Column name mapping: CIC-IDS2017 CSV columns → our FEATURE_COLS names
# ---------------------------------------------------------------------------
CIC_TO_OUR = {
    "Destination Port": "dst_port",
    "Flow Duration": "duration",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Fwd Packet Length Mean": "mean_pkt_size",
    "Fwd Packet Length Std": "std_pkt_size",
    "Bwd Packet Length Mean": "bwd_pkt_mean",
    "Flow Bytes/s": "bytes_per_sec",
    "Flow Packets/s": "packets_per_sec",
    "Flow IAT Mean": "mean_iat",
    "Flow IAT Std": "std_iat",
    "Flow IAT Max": "max_iat",
    "Flow IAT Min": "min_iat",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "FIN Flag Count": "fin_count",
    "SYN Flag Count": "syn_count",
    "RST Flag Count": "rst_count",
    "ACK Flag Count": "ack_count",
    "Average Packet Size": "mean_pkt_size",
    "Init_Win_bytes_forward": "avg_window_size",
    "Init_Win_bytes_backward": "init_win_bwd",
}

# ---------------------------------------------------------------------------
# Persistence paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
MODEL_DIR = os.path.join(SCRIPT_DIR, "model_artifacts")
MODEL_DIR_RF = os.path.join(MODEL_DIR, "rf_model.joblib")
MODEL_DIR_IF = os.path.join(MODEL_DIR, "if_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")


class FlowDetector:
    """
    Dual-mode flow anomaly detector.

    Modes:
      - "supervised"   : RandomForestClassifier trained on labelled CIC-IDS2017
      - "unsupervised" : IsolationForest trained on unlabelled flow records
      - None           : not yet trained
    """

    def __init__(self):
        self.rf_model: RandomForestClassifier | None = None
        self.if_model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.mode: str | None = None
        self.training_info: dict = {}  # stores imbalance context

    @property
    def is_trained(self) -> bool:
        return self.mode is not None

    # ------------------------------------------------------------------
    # Supervised training
    # ------------------------------------------------------------------
    def fit_supervised(self, train_csv_path: str):
        """
        Train RandomForestClassifier on the real CIC-IDS2017 training split.

        Pipeline to handle extreme imbalance:
          1. Undersample majority (BENIGN) to 10× minority count
          2. SMOTE oversample minority to match majority
          3. StandardScaler + RandomForest with class_weight="balanced"

        This avoids SMOTE being drowned by 200k majority samples and
        actually creates meaningful synthetic attack patterns.
        """
        print(f"[FlowDetector] Loading supervised training data from {train_csv_path}")
        df = pd.read_csv(train_csv_path)

        # Map CIC-IDS2017 columns → our names
        rename = {cic: our for cic, our in CIC_TO_OUR.items() if cic in df.columns}
        df = df.rename(columns=rename)

        # Derive fwd_bwd_ratio if not present
        if "fwd_bwd_ratio" not in df.columns and "fwd_packets" in df.columns:
            bwd = df["bwd_packets"].replace(0, 1)
            df["fwd_bwd_ratio"] = (df["fwd_packets"] / bwd).round(4)

        # Fill missing features with 0
        for col in FEATURE_COLS:
            if col not in df.columns:
                df[col] = 0.0

        X = df[FEATURE_COLS].fillna(0).values.astype(float)
        X = np.where(np.isfinite(X), X, 0.0)
        y = (df["Label"].str.strip() != "BENIGN").astype(int).values

        n_benign = int((y == 0).sum())
        n_attack = int((y == 1).sum())

        self.training_info = {
            "raw_benign": n_benign,
            "raw_attack": n_attack,
            "imbalance_ratio": f"{n_benign}:{n_attack}",
        }

        print(f"  Raw training set: {len(X)} rows")
        print(f"    BENIGN:       {n_benign}")
        print(f"    Infiltration: {n_attack}")
        print(f"    Imbalance:    {n_benign / max(n_attack, 1):.0f}:1")

        # ---- Step 1: Undersample majority to 10× minority ----------------
        target_majority = min(n_benign, n_attack * 10)
        if n_benign > target_majority:
            print(f"  Undersampling majority from {n_benign} → {target_majority}")
            rus = RandomUnderSampler(
                sampling_strategy={0: target_majority, 1: n_attack},
                random_state=42,
            )
            X, y = rus.fit_resample(X, y)
            print(f"    After undersample: BENIGN={(y == 0).sum()}, Attack={(y == 1).sum()}")

        # ---- Step 2: SMOTE oversample minority to match ------------------
        min_count = min((y == 0).sum(), (y == 1).sum())
        if min_count >= 2:
            k = min(5, min_count - 1)
            target_minority = (y == 0).sum()  # match majority count
            smote = SMOTE(
                sampling_strategy={0: (y == 0).sum(), 1: target_minority},
                random_state=42,
                k_neighbors=k,
            )
            X, y = smote.fit_resample(X, y)
            print(f"    After SMOTE: BENIGN={(y == 0).sum()}, Attack={(y == 1).sum()}")
        else:
            print("  WARNING: Too few minority samples for SMOTE — skipping")

        self.training_info["final_benign"] = int((y == 0).sum())
        self.training_info["final_attack"] = int((y == 1).sum())

        # ---- Step 3: Scale + Train ---------------------------------------
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        self.rf_model.fit(X_scaled, y)
        self.mode = "supervised"

        # Persist
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.rf_model, MODEL_DIR_RF)
        joblib.dump(self.scaler, SCALER_PATH)
        print(f"[FlowDetector] Supervised model saved to {MODEL_DIR_RF}")

    # ------------------------------------------------------------------
    # Unsupervised training
    # ------------------------------------------------------------------
    def fit_unsupervised(self, flow_records: list[dict]):
        """
        Train IsolationForest on unlabelled flow records.
        Only trains if len(flow_records) > 20.
        """
        if len(flow_records) < 20:
            print("[FlowDetector] Not enough records for unsupervised training "
                  f"({len(flow_records)} < 20)")
            return

        print(f"[FlowDetector] Training IsolationForest on {len(flow_records)} flows")
        X = self._records_to_array(flow_records)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.if_model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1,
        )
        self.if_model.fit(X_scaled)
        self.mode = "unsupervised"

        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.if_model, MODEL_DIR_IF)
        joblib.dump(self.scaler, SCALER_PATH)
        print(f"[FlowDetector] Unsupervised model saved to {MODEL_DIR_IF}")

    # ------------------------------------------------------------------
    # Predict
    # ------------------------------------------------------------------
    def predict(self, flow_dict: dict) -> int:
        """
        Return 1 if attack/anomaly predicted, 0 otherwise.
        """
        X = self._flow_to_array(flow_dict)

        if self.mode == "supervised" and self.rf_model is not None:
            X_scaled = self.scaler.transform(X) if self.scaler else X
            return int(self.rf_model.predict(X_scaled)[0])

        if self.mode == "unsupervised" and self.if_model is not None:
            X_scaled = self.scaler.transform(X) if self.scaler else X
            raw = self.if_model.predict(X_scaled)[0]
            return 1 if raw == -1 else 0

        return 0

    def predict_proba(self, flow_dict: dict) -> float:
        """
        Return probability of attack class (0.0–1.0).
        Only available in supervised mode.
        """
        if self.mode != "supervised" or self.rf_model is None:
            return 0.0

        X = self._flow_to_array(flow_dict)
        X_scaled = self.scaler.transform(X) if self.scaler else X
        proba = self.rf_model.predict_proba(X_scaled)[0]

        classes = list(self.rf_model.classes_)
        if 1 in classes:
            idx = classes.index(1)
            return float(proba[idx])
        return float(proba[-1])

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    @classmethod
    def load(cls) -> FlowDetector:
        """Load a persisted FlowDetector from disk."""
        detector = cls()
        if os.path.exists(MODEL_DIR_RF) and os.path.exists(SCALER_PATH):
            detector.rf_model = joblib.load(MODEL_DIR_RF)
            detector.scaler = joblib.load(SCALER_PATH)
            detector.mode = "supervised"
            print("[FlowDetector] Loaded supervised model from disk")
        elif os.path.exists(MODEL_DIR_IF) and os.path.exists(SCALER_PATH):
            detector.if_model = joblib.load(MODEL_DIR_IF)
            detector.scaler = joblib.load(SCALER_PATH)
            detector.mode = "unsupervised"
            print("[FlowDetector] Loaded unsupervised model from disk")
        return detector

    # ------------------------------------------------------------------
    # Internal array builders
    # ------------------------------------------------------------------
    def _flow_to_array(self, flow_dict: dict) -> np.ndarray:
        """Build a 1×N feature array from a single flow dict."""
        row = [float(flow_dict.get(col, 0.0)) for col in FEATURE_COLS]
        X = np.array(row, dtype=float).reshape(1, -1)
        X = np.where(np.isfinite(X), X, 0.0)
        return X

    @staticmethod
    def _records_to_array(flow_records: list[dict]) -> np.ndarray:
        """Build an M×N feature array from a list of flow dicts."""
        rows = []
        for rec in flow_records:
            row = [float(rec.get(col, 0.0)) for col in FEATURE_COLS]
            rows.append(row)
        X = np.array(rows, dtype=float)
        X = np.where(np.isfinite(X), X, 0.0)
        return X
