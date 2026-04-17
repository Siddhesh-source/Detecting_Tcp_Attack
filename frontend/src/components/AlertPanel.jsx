import React from 'react';

const LAYER_COLORS = {
  Transport: { bg: '#4488ff18', color: '#4488ff', border: '#4488ff44' },
  Network: { bg: '#aa44ff18', color: '#aa44ff', border: '#aa44ff44' },
  Derived: { bg: '#00ff8818', color: '#00ff88', border: '#00ff8844' },
};

function parseReason(r) { const m = r.match(/^([\w/]+):\s*(.+)$/); return m ? { layer: m[1], text: m[2] } : { layer: '', text: r }; }
function badgeStyle(l) { if (l.includes('Transport')) return LAYER_COLORS.Transport; if (l.includes('Network')) return LAYER_COLORS.Network; return LAYER_COLORS.Derived; }
function severityClass(score) { if (score >= 70) return 'alert-severity-critical'; if (score >= 40) return 'alert-severity-high'; return 'alert-severity-medium'; }

export default function AlertPanel({ alerts }) {
  return (
    <div>
      <h2>Alerts <span style={{ color: '#ff4444', fontFamily: 'JetBrains Mono' }}>({alerts.length})</span></h2>
      {alerts.length === 0 && <p style={{ color: '#6b7094', textAlign: 'center', padding: 24, fontSize: '0.8rem' }}>No alerts above threshold</p>}
      <div className="alert-list">
        {alerts.map((a, i) => {
          const reasons = (a.alert_reasons || '').split(';').map(r => r.trim()).filter(Boolean);
          const layer = a.tcp_layer || 'Transport';
          const bs = badgeStyle(layer);
          const score = a.suspicion_score || 0;
          return (
            <div className="alert-item" key={i}>
              <div className="alert-header">
                <span className={`alert-severity-dot ${severityClass(score)}`} />
                <span className="alert-layer-badge" style={{ background: bs.bg, color: bs.color, borderColor: bs.border }}>{layer}</span>
                <span className="alert-flow-id">{a.flow_id}</span>
                <span className="alert-score">{score.toFixed(0)}</span>
              </div>
              <div className="alert-ips">{a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}</div>
              {reasons.length > 0 && (
                <ul className="alert-reasons">
                  {reasons.map((r, j) => { const p = parseReason(r); return <li key={j} className="alert-reason-item">{p.text}</li>; })}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
