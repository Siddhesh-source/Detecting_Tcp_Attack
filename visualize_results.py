"""
Generate confusion matrix and visualization plots for ML model evaluation.
"""
import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score
)

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from ml_model import FlowDetector, FEATURE_COLS, CIC_TO_OUR

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_CSV = os.path.join(SCRIPT_DIR, "data", "processed", "test.csv")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "results")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_test_data(test_csv_path):
    """Load and prepare test data."""
    print(f"Loading test data from {test_csv_path}")
    df = pd.read_csv(test_csv_path)
    
    # Rename columns
    rename = {cic: our for cic, our in CIC_TO_OUR.items() if cic in df.columns}
    df = df.rename(columns=rename)
    
    # Derive fwd_bwd_ratio
    if "fwd_bwd_ratio" not in df.columns and "fwd_packets" in df.columns:
        bwd = df["bwd_packets"].replace(0, 1)
        df["fwd_bwd_ratio"] = (df["fwd_packets"] / bwd).round(4)
    
    # Fill missing features
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0
    
    X = df[FEATURE_COLS].fillna(0).values.astype(float)
    X = np.where(np.isfinite(X), X, 0.0)
    y = (df["Label"].str.strip() != "BENIGN").astype(int).values
    
    return X, y, df


def plot_confusion_matrix(y_true, y_pred, output_path):
    """Generate confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['BENIGN', 'ATTACK'],
                yticklabels=['BENIGN', 'ATTACK'])
    plt.title('Confusion Matrix', fontsize=16, fontweight='bold')
    plt.ylabel('Actual', fontsize=12)
    plt.xlabel('Predicted', fontsize=12)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved confusion matrix to {output_path}")
    plt.close()
    
    return cm


def plot_roc_curve(y_true, y_proba, output_path):
    """Generate ROC curve."""
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, 
             label=f'ROC curve (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curve', fontsize=16, fontweight='bold')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved ROC curve to {output_path}")
    plt.close()
    
    return roc_auc


def plot_precision_recall_curve(y_true, y_proba, output_path):
    """Generate Precision-Recall curve."""
    precision, recall, _ = precision_recall_curve(y_true, y_proba)
    avg_precision = average_precision_score(y_true, y_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color='blue', lw=2,
             label=f'PR curve (AP = {avg_precision:.4f})')
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curve', fontsize=16, fontweight='bold')
    plt.legend(loc="lower left")
    plt.grid(alpha=0.3)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved Precision-Recall curve to {output_path}")
    plt.close()
    
    return avg_precision


def plot_feature_importance(model, output_path):
    """Generate feature importance bar chart."""
    if model.mode != "supervised" or model.rf_model is None:
        print("Feature importance only available for supervised models")
        return
    
    importances = model.rf_model.feature_importances_
    n_features = min(15, len(importances))
    indices = np.argsort(importances)[::-1][:n_features]
    
    # Use FEATURE_COLS if indices are within range, otherwise use generic names
    feature_names = []
    for i in indices:
        if i < len(FEATURE_COLS):
            feature_names.append(FEATURE_COLS[i])
        else:
            feature_names.append(f'feature_{i}')
    
    plt.figure(figsize=(10, 8))
    plt.barh(range(len(indices)), importances[indices], color='steelblue')
    plt.yticks(range(len(indices)), feature_names)
    plt.xlabel('Importance', fontsize=12)
    plt.title(f'Top {n_features} Feature Importances', fontsize=16, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved feature importance to {output_path}")
    plt.close()


def plot_class_distribution(y_true, output_path):
    """Generate class distribution bar chart."""
    unique, counts = np.unique(y_true, return_counts=True)
    labels = ['BENIGN', 'ATTACK']
    
    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, counts, color=['green', 'red'], alpha=0.7)
    plt.ylabel('Count', fontsize=12)
    plt.title('Class Distribution in Test Set', fontsize=16, fontweight='bold')
    
    # Add count labels on bars
    for bar, count in zip(bars, counts):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(count)}\n({count/sum(counts)*100:.2f}%)',
                ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved class distribution to {output_path}")
    plt.close()


def main():
    """Main execution."""
    print("="*60)
    print("ML Model Evaluation and Visualization")
    print("="*60)
    
    # Load model
    print("\n1. Loading trained model...")
    model = FlowDetector.load()
    
    if not model.is_trained:
        print("ERROR: No trained model found. Please train the model first.")
        return
    
    print(f"   Model mode: {model.mode}")
    
    # Load test data
    print("\n2. Loading test data...")
    if not os.path.exists(TEST_CSV):
        print(f"ERROR: Test data not found at {TEST_CSV}")
        return
    
    X, y_true, df = load_test_data(TEST_CSV)
    print(f"   Test samples: {len(y_true)}")
    print(f"   BENIGN: {(y_true == 0).sum()}")
    print(f"   ATTACK: {(y_true == 1).sum()}")
    
    # Make predictions
    print("\n3. Making predictions...")
    if model.scaler is not None:
        X_scaled = model.scaler.transform(X)
    else:
        X_scaled = X
    
    if model.mode == "supervised" and model.rf_model is not None:
        y_pred = model.rf_model.predict(X_scaled)
        y_proba = model.rf_model.predict_proba(X_scaled)
        classes = list(model.rf_model.classes_)
        idx = classes.index(1) if 1 in classes else -1
        y_proba_attack = y_proba[:, idx]
    else:
        print("ERROR: Only supervised models supported for full visualization")
        return
    
    # Generate confusion matrix
    print("\n4. Generating confusion matrix...")
    cm = plot_confusion_matrix(y_true, y_pred, 
                               os.path.join(OUTPUT_DIR, 'confusion_matrix.png'))
    
    tn, fp, fn, tp = cm.ravel()
    print(f"\n   Confusion Matrix:")
    print(f"   True Negatives:  {tn}")
    print(f"   False Positives: {fp}")
    print(f"   False Negatives: {fn}")
    print(f"   True Positives:  {tp}")
    
    # Print classification report
    print("\n5. Classification Report:")
    print(classification_report(y_true, y_pred, 
                               target_names=['BENIGN', 'ATTACK'],
                               digits=4))
    
    # Generate plots
    print("\n6. Generating visualization plots...")
    plot_class_distribution(y_true, os.path.join(OUTPUT_DIR, 'class_distribution.png'))
    
    if len(np.unique(y_true)) > 1:
        roc_auc = plot_roc_curve(y_true, y_proba_attack, 
                                 os.path.join(OUTPUT_DIR, 'roc_curve.png'))
        avg_precision = plot_precision_recall_curve(y_true, y_proba_attack,
                                                    os.path.join(OUTPUT_DIR, 'precision_recall_curve.png'))
        print(f"   ROC AUC: {roc_auc:.4f}")
        print(f"   Average Precision: {avg_precision:.4f}")
    
    plot_feature_importance(model, os.path.join(OUTPUT_DIR, 'feature_importance.png'))
    
    print("\n" + "="*60)
    print(f"All results saved to: {OUTPUT_DIR}")
    print("="*60)


if __name__ == "__main__":
    main()
