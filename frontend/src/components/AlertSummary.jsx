import React from 'react';

const LAYER_COLORS = { Transport: '#4488ff', Network: '#aa44ff', Derived: '#00ff88' };
const LAYERS = [
  { name: 'Application', osi: 'L7', color: '#ff4444', empty: true },
  { name: 'Transport', osi: 'L4', color: '#4488ff' },
  { name: 'Network', osi: 'L3', color: '#aa44ff' },
  { name: 'Derived', osi: '—', color: '#00ff88' },
];

export default function AlertSummary({ alerts, stats, metrics, featureImportance, layerStats, onSelectFlow }) {
  const sevClass = (s) => s >= 70 ? 'alert-sev-crit' : s >= 40 ? 'alert-sev-high' : 'alert-sev-med';

  return (
    <div className="alert-summary">
      {/* LEFT: Alert Feed */}
      <div className="summary-left">
        <div className="alert-feed">
          <h3>⚠ Alert Feed ({alerts.length})</h3>
          {!alerts.length && <div style={{ color: 'var(--muted)', textAlign: 'center', padding: 28, fontSize: '0.78rem' }}>No alerts above threshold</div>}
          <div className="alert-list">
            {alerts.slice(0, 30).map((a, i) => (
              <div key={i} className="alert-item" onClick={() => onSelectFlow(a)}>
                <div className="alert-head">
                  <span className={`alert-sev ${sevClass(a.suspicion_score || 0)}`} />
                  <span className="alert-fid">{a.src_ip} → {a.dst_ip}:{a.dst_port}</span>
                  <span className="alert-scr">{a.suspicion_score?.toFixed(0)}</span>
                </div>
                <div className="alert-ips">{a.tcp_layer || 'Transport'}</div>
                <div className="alert-reason">{((a.alert_reasons || '').split(';')[0] || '').replace(/^[\w/]+:\s*/, '')}</div>
                <div className="alert-inspect">Inspect →</div>
              </div>
            ))}
          </div>
        </div>
      </div>
      {/* RIGHT: KPIs + Model + OSI */}
      <div className="summary-right">
        <div className="summary-kpi"><div className="summary-kpi-val c-green">{stats.total_flows ?? '—'}</div><div className="summary-kpi-label">Total Flows</div></div>
        <div className="summary-kpi"><div className="summary-kpi-val c-red">{stats.total_alerts ?? '—'}</div><div className="summary-kpi-label">Active Alerts</div></div>
        <div className="summary-kpi"><div className="summary-kpi-val c-yellow">{stats.avg_suspicion_score?.toFixed(1) ?? '—'}</div><div className="summary-kpi-label">Avg Score</div></div>
        <div className="summary-kpi"><div className="summary-kpi-val c-blue">{new Set(alerts.map(a => a.src_ip)).size}</div><div className="summary-kpi-label">Unique IPs</div></div>
        {/* Model mini */}
        <div className="model-mini" style={{ gridColumn: '1 / 3' }}>
          <h3>Model Summary</h3>
          <div className="model-row"><span className="model-label">Recall</span><span className="model-val" style={{ color: metrics?.recall > 0.7 ? 'var(--green)' : 'var(--red)' }}>{metrics?.recall != null ? `${(metrics.recall * 100).toFixed(1)}%` : '—'}</span></div>
          <div className="model-row"><span className="model-label">F1</span><span className="model-val">{metrics?.f1 != null ? `${(metrics.f1 * 100).toFixed(1)}%` : '—'}</span></div>
          <div className="model-row"><span className="model-label">ROC-AUC</span><span className="model-val">{metrics?.roc_auc != null ? `${(metrics.roc_auc * 100).toFixed(1)}%` : '—'}</span></div>
          <div className="model-row"><span className="model-label">Detected</span><span className="model-val">{metrics?.attack_detected ?? '—'} / {metrics?.test_attack ?? '—'}</span></div>
        </div>
        {/* OSI mini */}
        <div className="osi-mini" style={{ gridColumn: '3 / 5' }}>
          <h3>OSI Layers</h3>
          {LAYERS.map(l => {
            const cnt = layerStats?.[l.name] || 0;
            return (
              <div key={l.name} className="osi-row" style={{ opacity: l.empty ? 0.35 : 1 }}>
                <span className="osi-dot" style={{ background: l.empty ? '#444' : l.color }} />
                <span className="osi-name">{l.name} <span style={{ fontFamily: 'var(--mono)', fontSize: '0.65rem', color: 'var(--muted)' }}>({l.osi})</span></span>
                <span className={`osi-cnt ${cnt > 0 ? 'osi-cnt-has' : 'osi-cnt-none'}`}>{cnt}</span>
              </div>
            );
          })}
          <div style={{ fontSize: '0.6rem', color: '#3a3f58', marginTop: 4, fontStyle: 'italic' }}>No payload inspection</div>
        </div>
      </div>
    </div>
  );
}
