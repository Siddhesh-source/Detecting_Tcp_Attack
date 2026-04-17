"""
Evaluator – honest model evaluation for extremely imbalanced data.

Provides:
  - evaluate_model()          → single test-set metrics
  - evaluate_cross_validate() → stratified 5-fold CV with honest metrics
  - get_feature_importance()  → top-10 features with OSI layer tags
  - generate_evaluation_report() → markdown report with imbalance warnings
  - init_evaluator()         → run once at startup, cache result
"""

from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

from feature_extractor import FEATURE_LAYER_MAP
from ml_model import CIC_TO_OUR, FEATURE_COLS, FlowDetector

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
TRAIN_CSV = os.path.join(PROJECT_DIR, "data", "processed", "train.csv")
TEST_CSV = os.path.join(PROJECT_DIR, "data", "processed", "test.csv")
PROCESSED_CSV = os.path.join(PROJECT_DIR, "data", "processed", "cic_ids2017_processed.csv")
METRICS_CACHE_PATH = os.path.join(SCRIPT_DIR, "model_artifacts", "metrics.json")
REPORT_PATH = os.path.join(PROJECT_DIR, "docs", "evaluation_report.md")

# ---------------------------------------------------------------------------
# Detection rules constant (for report generation)
# ---------------------------------------------------------------------------
SCORING_RULES = [
    {
        "id": 1,
        "points": 30,
        "condition": "std_iat < 0.01 and total_packets > 10",
        "reason": "Transport/Derived: Low IAT variance — periodic covert channel pattern",
        "layer": "Transport / Derived",
    },
    {
        "id": 2,
        "points": 25,
        "condition": "duration > 60 and packets_per_sec < 0.5",
        "reason": "Derived: Long-duration low-rate flow — covert persistence indicator",
        "layer": "Derived",
    },
    {
        "id": 3,
        "points": 20,
        "condition": "mean_pkt_size < 100 and total_packets > 10",
        "reason": "Network/Transport: Small packet dominance — possible data encoding",
        "layer": "Network / Transport",
    },
    {
        "id": 4,
        "points": 25,
        "condition": "fwd_bwd_ratio > 5",
        "reason": "Derived: Asymmetric flow — possible data exfiltration",
        "layer": "Derived",
    },
    {
        "id": 5,
        "points": 15,
        "condition": "burst_count > total_packets * 0.8",
        "reason": "Derived: High burst ratio — bursty-silent covert pattern",
        "layer": "Derived",
    },
    {
        "id": 6,
        "points": 10,
        "condition": "retransmit_count > total_packets * 0.1",
        "reason": "Transport: High retransmission rate — possible channel manipulation",
        "layer": "Transport",
    },
]

# ---------------------------------------------------------------------------
# Cached results (populated at startup)
# ---------------------------------------------------------------------------
_cached_metrics: dict | None = None
_cached_report: str | None = None


# =======================================================================
# Data helpers
# =======================================================================
def _load_and_prepare(csv_path: str):
    """Load a CIC-IDS2017 CSV and return (X, y, df) aligned with FEATURE_COLS."""
    df = pd.read_csv(csv_path)

    rename = {cic: our for cic, our in CIC_TO_OUR.items() if cic in df.columns}
    df = df.rename(columns=rename)

    if "fwd_bwd_ratio" not in df.columns and "fwd_packets" in df.columns:
        bwd = df["bwd_packets"].replace(0, 1)
        df["fwd_bwd_ratio"] = (df["fwd_packets"] / bwd).round(4)

    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0

    X = df[FEATURE_COLS].fillna(0).values.astype(float)
    X = np.where(np.isfinite(X), X, 0.0)
    y = (df["Label"].str.strip() != "BENIGN").astype(int).values

    return X, y, df


# =======================================================================
# Single test-set evaluation (for the /metrics endpoint)
# =======================================================================
def evaluate_model(model: FlowDetector, test_csv_path: str = TEST_CSV) -> dict:
    """
    Evaluate the trained model on the held-out test set.
    Returns metrics with imbalance warnings.
    """
    if not model.is_trained:
        return {"error": "Model not trained."}

    if not os.path.exists(test_csv_path):
        return {"error": f"Test data not found at {test_csv_path}"}

    X, y_true, _ = _load_and_prepare(test_csv_path)

    if model.scaler is not None:
        X_scaled = model.scaler.transform(X)
    else:
        X_scaled = X

    # Predict
    if model.mode == "supervised" and model.rf_model is not None:
        y_pred = model.rf_model.predict(X_scaled)
        roc_auc = 0.0
        try:
            if len(np.unique(y_true)) > 1:
                y_proba = model.rf_model.predict_proba(X_scaled)
                classes = list(model.rf_model.classes_)
                idx = classes.index(1) if 1 in classes else -1
                roc_auc = roc_auc_score(y_true, y_proba[:, idx])
        except Exception:
            pass
    elif model.mode == "unsupervised" and model.if_model is not None:
        raw = model.if_model.predict(X_scaled)
        y_pred = np.where(raw == -1, 1, 0)
        roc_auc = 0.0
    else:
        return {"error": "Model has no valid predictor"}

    # Metrics
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn = int(cm[0][0])
    fp = int(cm[0][1]) if cm.shape[0] > 1 else 0
    fn = int(cm[1][0]) if cm.shape[0] > 1 else 0
    tp = int(cm[1][1]) if cm.shape[0] > 1 else 0

    n_benign = int((y_true == 0).sum())
    n_attack = int((y_true == 1).sum())
    minority_pct = n_attack / len(y_true) * 100

    metrics = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "total_test_samples": int(len(y_true)),
        "test_benign": n_benign,
        "test_attack": n_attack,
        "attack_detected": int(tp),
        "attack_missed": int(fn),
        "false_positives": int(fp),
        "minority_class_pct": round(minority_pct, 4),
        "imbalance_warning": minority_pct < 5.0,
    }

    # Persist
    os.makedirs(os.path.dirname(METRICS_CACHE_PATH), exist_ok=True)
    with open(METRICS_CACHE_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    return metrics


# =======================================================================
# Stratified 5-fold cross-validation (honest metrics)
# =======================================================================
def evaluate_cross_validate(csv_path: str = PROCESSED_CSV) -> dict:
    """
    Run stratified 5-fold cross-validation on the FULL processed dataset.

    Each fold:
      1. Undersample majority to 10× minority
      2. SMOTE minority to match
      3. Train RF, evaluate on held-out fold

    Returns mean ± std for precision, recall, F1, ROC-AUC.
    Much more reliable than single split with 7 test samples.
    """
    if not os.path.exists(csv_path):
        return {"error": f"Processed data not found at {csv_path}"}

    print("[Evaluator] Running stratified 5-fold cross-validation...")
    X, y, _ = _load_and_prepare(csv_path)
    n_attack = int((y == 1).sum())
    n_benign = int((y == 0).sum())
    print(f"  Dataset: {len(y)} rows, {n_benign} BENIGN, {n_attack} Infiltration")

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    fold_results = []
    for fold_i, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        n_train_attack = int((y_train == 1).sum())
        n_train_benign = int((y_train == 0).sum())

        # Undersample majority to 10× minority
        target_majority = min(n_train_benign, n_train_attack * 10)
        if n_train_benign > target_majority and n_train_attack >= 2:
            rus = RandomUnderSampler(
                sampling_strategy={0: target_majority, 1: n_train_attack},
                random_state=42,
            )
            X_train, y_train = rus.fit_resample(X_train, y_train)

        # SMOTE to balance
        min_count = min((y_train == 0).sum(), (y_train == 1).sum())
        if min_count >= 2:
            k = min(5, min_count - 1)
            target = (y_train == 0).sum()
            smote = SMOTE(
                sampling_strategy={0: target, 1: target},
                random_state=42,
                k_neighbors=k,
            )
            X_train, y_train = smote.fit_resample(X_train, y_train)

        # Scale
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        # Train
        clf = RandomForestClassifier(
            n_estimators=100, random_state=42,
            class_weight="balanced", n_jobs=-1,
        )
        clf.fit(X_train_s, y_train)

        # Evaluate on UNSAMPLED test fold
        y_pred = clf.predict(X_test_s)
        y_proba = clf.predict_proba(X_test_s)
        classes = list(clf.classes_)
        idx = classes.index(1) if 1 in classes else -1

        fold_prec = precision_score(y_test, y_pred, zero_division=0)
        fold_rec = recall_score(y_test, y_pred, zero_division=0)
        fold_f1 = f1_score(y_test, y_pred, zero_division=0)
        fold_auc = 0.0
        try:
            if len(np.unique(y_test)) > 1:
                fold_auc = roc_auc_score(y_test, y_proba[:, idx])
        except Exception:
            pass

        fold_results.append({
            "precision": fold_prec,
            "recall": fold_rec,
            "f1": fold_f1,
            "roc_auc": fold_auc,
            "test_attack": int((y_test == 1).sum()),
            "test_benign": int((y_test == 0).sum()),
            "tp": int(((y_test == 1) & (y_pred == 1)).sum()),
            "fn": int(((y_test == 1) & (y_pred == 0)).sum()),
        })

        fold_rec_pct = round(fold_rec * 100, 1)
        print(f"  Fold {fold_i+1}/5: precision={fold_prec:.4f}, recall={fold_rec_pct}%, "
              f"F1={fold_f1:.4f}, AUC={fold_auc:.4f}, "
              f"attacks={int((y_test==1).sum())}, caught={int(((y_test==1)&(y_pred==1)).sum())}")

    # Aggregate
    precs = [f["precision"] for f in fold_results]
    recs = [f["recall"] for f in fold_results]
    f1s = [f["f1"] for f in fold_results]
    aucs = [f["roc_auc"] for f in fold_results]

    total_tp = sum(f["tp"] for f in fold_results)
    total_fn = sum(f["fn"] for f in fold_results)
    total_attack = sum(f["test_attack"] for f in fold_results)

    cv_metrics = {
        "method": "stratified_5fold_cv",
        "precision_mean": round(float(np.mean(precs)), 4),
        "precision_std": round(float(np.std(precs)), 4),
        "recall_mean": round(float(np.mean(recs)), 4),
        "recall_std": round(float(np.std(recs)), 4),
        "f1_mean": round(float(np.mean(f1s)), 4),
        "f1_std": round(float(np.std(f1s)), 4),
        "roc_auc_mean": round(float(np.mean(aucs)), 4),
        "roc_auc_std": round(float(np.std(aucs)), 4),
        "total_attacks_across_folds": total_attack,
        "total_detected_across_folds": total_tp,
        "total_missed_across_folds": total_fn,
        "attack_detection_rate": round(total_tp / max(total_attack, 1) * 100, 1),
        "folds": fold_results,
    }

    print(
        f"[Evaluator] CV Results: recall={cv_metrics['recall_mean']:.4f}"
        f"±{cv_metrics['recall_std']:.4f}, "
        f"F1={cv_metrics['f1_mean']:.4f}±{cv_metrics['f1_std']:.4f}, "
        f"detection_rate={cv_metrics['attack_detection_rate']}%"
    )

    return cv_metrics


# =======================================================================
# Feature importance
# =======================================================================
def get_feature_importance(model: FlowDetector) -> list[dict]:
    """
    Return top 10 features by importance from the RF model.
    Each: {"feature", "importance", "layer"}.
    Returns [] if not supervised.
    """
    if model.mode != "supervised" or model.rf_model is None:
        return []

    importances = model.rf_model.feature_importances_
    paired = list(zip(FEATURE_COLS, importances))
    paired.sort(key=lambda x: x[1], reverse=True)

    top = []
    for feature, importance in paired[:10]:
        layer = FEATURE_LAYER_MAP.get(feature, "Derived")
        top.append({
            "feature": feature,
            "importance": round(float(importance), 6),
            "layer": layer,
        })
    return top


# =======================================================================
# Report generation
# =======================================================================
def generate_evaluation_report(
    model: FlowDetector,
    test_metrics: dict | None = None,
    cv_metrics: dict | None = None,
) -> str:
    """
    Produce a markdown evaluation report with honest metrics and warnings.
    """
    if test_metrics is None:
        test_metrics = _cached_metrics or {}
    if cv_metrics is None:
        cv_metrics = {}

    def pct(val):
        if isinstance(val, (int, float)):
            return f"{val * 100:.1f}%"
        return str(val)

    cm = test_metrics.get("confusion_matrix", [[0, 0], [0, 0]])
    tn = cm[0][0] if cm else 0
    fp = cm[0][1] if cm else 0
    fn = cm[1][0] if len(cm) > 1 else 0
    tp = cm[1][1] if len(cm) > 1 else 0

    n_attack_test = test_metrics.get("test_attack", 0)
    minority_pct = test_metrics.get("minority_class_pct", 0)

    fi = get_feature_importance(model)[:5]

    lines = [
        "## Detection Evaluation Report",
        "",
        "**Dataset**: CIC-IDS2017 (Infiltration subset)",
        "",
        "**Model**: Random Forest (100 estimators, undersample + SMOTE)",
        "",
        "**Train/Test Split**: 80/20 stratified",
        "",
        "### ⚠️ Class Imbalance Warning",
        "",
        f"The test set contains only **{n_attack_test} attack samples** out of "
        f"{test_metrics.get('total_test_samples', 0)} total "
        f"({minority_pct:.2f}%). This means:",
        "",
        "- **Accuracy is misleading**: predicting BENIGN for everything gives 99.99% accuracy",
        "- **Precision is inflated**: with so few attacks, false positives are unlikely by chance",
        "- **Recall is the honest metric**: did we catch the real attacks?",
        "- **All single-split metrics are unreliable** with ≤7 attack test samples",
        "",
        "### Single-Split Results (Held-Out Test Set)",
        "",
        "| Metric | Score | Note |",
        "|--------|-------|------|",
    ]

    acc_note = "⚠️ Misleading — majority class dominates" if minority_pct < 1 else ""
    prec_note = "⚠️ Inflated by class imbalance" if minority_pct < 1 else ""
    rec_note = "✅ Honest metric" if test_metrics.get("recall", 0) > 0 else ""

    lines.extend([
        f"| Accuracy | {pct(test_metrics.get('accuracy'))} | {acc_note} |",
        f"| Precision | {pct(test_metrics.get('precision'))} | {prec_note} |",
        f"| Recall | {pct(test_metrics.get('recall'))} | {rec_note} |",
        f"| F1 Score | {pct(test_metrics.get('f1'))} | |",
        f"| ROC-AUC | {pct(test_metrics.get('roc_auc'))} | |",
        "",
        "### Confusion Matrix",
        "",
        "| | Predicted BENIGN | Predicted ATTACK |",
        "|---|---|---|",
        f"| Actual BENIGN | {tn} | {fp} |",
        f"| Actual ATTACK | {fn} | {tp} |",
        "",
    ])

    # Cross-validation results
    if cv_metrics and "error" not in cv_metrics:
        lines.extend([
            "### Stratified 5-Fold Cross-Validation (More Reliable)",
            "",
            f"Attack detection rate across all folds: "
            f"**{cv_metrics.get('attack_detection_rate', 0)}%** "
            f"({cv_metrics.get('total_detected_across_folds', 0)}/"
            f"{cv_metrics.get('total_attacks_across_folds', 0)} attacks)",
            "",
            "| Metric | Mean | Std Dev |",
            "|--------|------|---------|",
            f"| Precision | {cv_metrics.get('precision_mean', 0):.4f} | "
            f"±{cv_metrics.get('precision_std', 0):.4f} |",
            f"| Recall | {cv_metrics.get('recall_mean', 0):.4f} | "
            f"±{cv_metrics.get('recall_std', 0):.4f} |",
            f"| F1 Score | {cv_metrics.get('f1_mean', 0):.4f} | "
            f"±{cv_metrics.get('f1_std', 0):.4f} |",
            f"| ROC-AUC | {cv_metrics.get('roc_auc_mean', 0):.4f} | "
            f"±{cv_metrics.get('roc_auc_std', 0):.4f} |",
            "",
        ])

    # Feature importance
    lines.extend([
        "### Feature Importance (Top 5)",
        "",
    ])
    if fi:
        for item in fi:
            lines.append(
                f"- **{item['feature']}** — importance: "
                f"{item['importance']:.6f} (OSI: {item['layer']})"
            )
    else:
        lines.append("_No feature importance available_")

    # Rules
    lines.extend([
        "",
        "### Detection Rules Summary",
        "",
        "| # | Condition | Points | OSI Layer |",
        "|---|-----------|--------|-----------|",
    ])
    for rule in SCORING_RULES:
        lines.append(
            f"| {rule['id']} | `{rule['condition']}` | "
            f"{rule['points']} | {rule['layer']} |"
        )

    return "\n".join(lines)


def save_evaluation_report(report: str) -> str:
    """Persist the evaluation report to docs/evaluation_report.md."""
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)
    return REPORT_PATH


def get_cached_metrics() -> dict | None:
    return _cached_metrics


def get_cached_report() -> str | None:
    return _cached_report


def init_evaluator(model: FlowDetector) -> dict:
    """
    Run evaluation at startup:
      1. Single test-set evaluation
      2. Stratified 5-fold cross-validation
      3. Generate and save report
    """
    global _cached_metrics, _cached_report

    if not model.is_trained:
        _cached_metrics = {"error": "Model not trained at startup"}
        _cached_report = generate_evaluation_report(model, _cached_metrics)
        return _cached_metrics

    if not os.path.exists(TEST_CSV):
        _cached_metrics = {"error": f"Test data not found at {TEST_CSV}"}
        _cached_report = generate_evaluation_report(model, _cached_metrics)
        return _cached_metrics

    # 1. Single test-set evaluation
    _cached_metrics = evaluate_model(model, TEST_CSV)
    print(f"[Evaluator] Test set: accuracy={_cached_metrics.get('accuracy')}, "
          f"recall={_cached_metrics.get('recall')}, "
          f"f1={_cached_metrics.get('f1')}, "
          f"attacks={_cached_metrics.get('test_attack')}, "
          f"detected={_cached_metrics.get('attack_detected')}, "
          f"missed={_cached_metrics.get('attack_missed')}")

    # 2. Cross-validation (uses full processed dataset)
    cv_metrics = {}
    if os.path.exists(PROCESSED_CSV):
        cv_metrics = evaluate_cross_validate(PROCESSED_CSV)

    # 3. Generate and save report
    _cached_report = generate_evaluation_report(model, _cached_metrics, cv_metrics)
    report_path = save_evaluation_report(_cached_report)
    print(f"[Evaluator] Report saved to {report_path}")

    return _cached_metrics
