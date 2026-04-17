import React from 'react';

export default function ImbalanceBanner({ metrics }) {
  if (!metrics || !metrics.imbalance_warning) return null;
  return (
    <div className="imbalance-banner">
      <div className="imbalance-icon">⚠️</div>
      <div className="imbalance-text">
        Dataset has <strong>{metrics.minority_class_pct?.toFixed(2)}%</strong> attack samples ({metrics.test_attack}/{metrics.total_test_samples}). Accuracy/precision are misleading — <strong>recall is the honest metric</strong>. Model caught <strong>{metrics.attack_detected}/{metrics.test_attack}</strong> attacks with <strong>{metrics.false_positives}</strong> false positives.
      </div>
    </div>
  );
}
