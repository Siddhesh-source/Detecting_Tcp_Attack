## Detection Evaluation Report

**Dataset**: CIC-IDS2017 (Infiltration subset)

**Model**: Random Forest (100 estimators, undersample + SMOTE)

**Train/Test Split**: 80/20 stratified

### ⚠️ Class Imbalance Warning

The test set contains only **7 attack samples** out of 50558 total
(0.01%). This means:

- **Accuracy is misleading**: predicting BENIGN for everything gives 99.99% accuracy
- **Precision is inflated**: with so few attacks, false positives are unlikely by chance
- **Recall is the honest metric**: did we catch the real attacks?
- **All single-split metrics are unreliable** with ≤7 attack test samples

### Single-Split Results (Held-Out Test Set)

| Metric | Score | Note |
|--------|-------|------|
| Accuracy | 98.1% | ⚠️ Misleading — majority class dominates |
| Precision | 0.6% | ⚠️ Inflated by class imbalance |
| Recall | 85.7% | ✅ Honest metric |
| F1 Score | 1.2% | |
| ROC-AUC | 89.5% | |

### Confusion Matrix

| | Predicted BENIGN | Predicted ATTACK |
|---|---|---|
| Actual BENIGN | 49571 | 980 |
| Actual ATTACK | 1 | 6 |

### Stratified 5-Fold Cross-Validation (More Reliable)

Attack detection rate across all folds: **77.8%** (28/36 attacks)

| Metric | Mean | Std Dev |
|--------|------|---------|
| Precision | 0.0155 | ±0.0048 |
| Recall | 0.7786 | ±0.0655 |
| F1 Score | 0.0304 | ±0.0092 |
| ROC-AUC | 0.9436 | ±0.0667 |

### Feature Importance (Top 5)

- **mean_pkt_size** — importance: 0.216071 (OSI: Derived)
- **duration** — importance: 0.190317 (OSI: Derived)
- **fin_count** — importance: 0.134572 (OSI: Transport)
- **packets_per_sec** — importance: 0.129986 (OSI: Derived)
- **burst_count** — importance: 0.069130 (OSI: Derived)

### Detection Rules Summary

| # | Condition | Points | OSI Layer |
|---|-----------|--------|-----------|
| 1 | `std_iat < 0.01 and total_packets > 10` | 30 | Transport / Derived |
| 2 | `duration > 60 and packets_per_sec < 0.5` | 25 | Derived |
| 3 | `mean_pkt_size < 100 and total_packets > 10` | 20 | Network / Transport |
| 4 | `fwd_bwd_ratio > 5` | 25 | Derived |
| 5 | `burst_count > total_packets * 0.8` | 15 | Derived |
| 6 | `retransmit_count > total_packets * 0.1` | 10 | Transport |