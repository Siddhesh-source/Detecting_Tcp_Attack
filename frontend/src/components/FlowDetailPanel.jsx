import React from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip } from 'chart.js';
ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

const LAYER_COLORS = { Transport: '#4488ff', Network: '#aa44ff', Derived: '#00ff88' };
const BASELINE = { duration: 15, total_packets: 50, packets_per_sec: 5, bytes_per_sec: 3000, mean_pkt_size: 400, std_iat: 0.1, fwd_bwd_ratio: 2, syn_count: 3, rst_count: 0, retransmit_count: 0, avg_window_size: 6000, burst_count: 5 };

export default function FlowDetailPanel({ flow, onClose }) {
  if (!flow) return null;
  const s = flow.suspicion_score || 0;
  const scoreColor = s >= 70 ? 'var(--red)' : s >= 40 ? 'var(--yellow)' : 'var(--green)';
  const reasons = (flow.alert_reasons || '').split(';').map(r => r.trim()).filter(Boolean);
  const layer = flow.tcp_layer || 'Transport';

  const comparisons = [
    { key: 'duration', label: 'Duration', unit: 's' },
    { key: 'packets_per_sec', label: 'Pkts/s', unit: '' },
    { key: 'bytes_per_sec', label: 'Bytes/s', unit: '' },
    { key: 'mean_pkt_size', label: 'Pkt Size', unit: 'B' },
    { key: 'std_iat', label: 'IAT Std', unit: 's' },
    { key: 'fwd_bwd_ratio', label: 'Fwd/Bwd', unit: '' },
    { key: 'rst_count', label: 'RST', unit: '' },
  ];

  return (
    <div className="detail-overlay">
      <button className="detail-close" onClick={onClose}>✕</button>

      <div className="detail-section">
        <div className="detail-score-big" style={{ color: scoreColor }}>{s.toFixed(0)}</div>
        <div style={{ fontSize: '0.72rem', color: 'var(--muted)' }}>Suspicion Score — <strong style={{ color: scoreColor }}>{s >= 70 ? 'HIGH RISK' : s >= 40 ? 'MEDIUM' : 'LOW'}</strong></div>
      </div>

      <div className="detail-section">
        <h3>Flow Details</h3>
        <div className="detail-row"><span className="detail-key">Source</span><span className="detail-val">{flow.src_ip}:{flow.src_port}</span></div>
        <div className="detail-row"><span className="detail-key">Destination</span><span className="detail-val">{flow.dst_ip}:{flow.dst_port}</span></div>
        <div className="detail-row"><span className="detail-key">Duration</span><span className="detail-val">{flow.duration?.toFixed(2)}s</span></div>
        <div className="detail-row"><span className="detail-key">Packets</span><span className="detail-val">{flow.total_packets}</span></div>
        <div className="detail-row"><span className="detail-key">Pkts/sec</span><span className="detail-val">{flow.packets_per_sec?.toFixed(2)}</span></div>
        <div className="detail-row"><span className="detail-key">OSI Layer</span><span className="detail-val" style={{ color: LAYER_COLORS[layer] || 'var(--text)' }}>{layer}</span></div>
        <div className="detail-row"><span className="detail-key">Prediction</span><span className="detail-val" style={{ color: flow.predicted_label === 'ATTACK' ? 'var(--red)' : 'var(--green)' }}>{flow.predicted_label}</span></div>
      </div>

      {reasons.length > 0 && (
        <div className="detail-section">
          <h3>Why Flagged</h3>
          {reasons.map((r, i) => {
            const parsed = r.replace(/^[\w/]+:\s*/, '');
            return <div key={i} className="detail-reason">↳ {parsed}</div>;
          })}
        </div>
      )}

      <div className="detail-section">
        <h3>Current vs Normal Baseline</h3>
        {comparisons.map(c => {
          const val = flow[c.key] ?? 0;
          const base = BASELINE[c.key] || 1;
          const maxVal = Math.max(Math.abs(val), Math.abs(base)) * 1.2;
          const valPct = Math.min((Math.abs(val) / maxVal) * 100, 100);
          const basePct = Math.min((Math.abs(base) / maxVal) * 100, 100);
          const isAnomalous = c.key === 'std_iat' ? val < base * 0.1 : c.key === 'fwd_bwd_ratio' || c.key === 'rst_count' ? val > base * 2 : val > base * 3 || val < base * 0.1;
          return (
            <div key={c.key} className="detail-bar-row">
              <div className="detail-bar-label">
                <span>{c.label}</span>
                <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: isAnomalous ? 'var(--red)' : 'var(--text)' }}>{typeof val === 'number' ? val.toFixed(2) : val}{c.unit}</span>
              </div>
              <div className="detail-bar">
                <div className="detail-bar-fill" style={{ width: `${valPct}%`, background: isAnomalous ? 'var(--red)' : 'var(--blue)' }} />
              </div>
              <div className="detail-bar" style={{ marginTop: 2 }}>
                <div className="detail-bar-fill" style={{ width: `${basePct}%`, background: 'var(--border-light)' }} />
              </div>
            </div>
          );
        })}
        <div style={{ fontSize: '0.58rem', color: 'var(--muted)', marginTop: 6 }}>Top bar = current · Bottom bar = normal baseline</div>
      </div>
    </div>
  );
}
