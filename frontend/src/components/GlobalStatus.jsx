import React, { useState, useEffect, useRef } from 'react';

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  return `${m}m ago`;
}

export default function GlobalStatus({ connected, threatLevel, alertCount, capturing, captureIface, lastUpdate }) {
  const [timeStr, setTimeStr] = useState(timeAgo(lastUpdate));
  useEffect(() => { const iv = setInterval(() => setTimeStr(timeAgo(lastUpdate)), 5000); return () => clearInterval(iv); }, [lastUpdate]);

  const threatColor = threatLevel === 'HIGH' ? 'status-val-red' : threatLevel === 'MEDIUM' ? 'status-val-yellow' : 'status-val-green';
  const dotClass = threatLevel === 'HIGH' ? 'status-dot-bad' : threatLevel === 'MEDIUM' ? 'status-dot-warn' : 'status-dot-ok';
  const capClass = capturing ? (captureIface ? 'capture-tag-live' : 'capture-tag-pcap') : 'capture-tag-idle';
  const capText = capturing ? (captureIface ? `LIVE (${captureIface})` : 'PCAP') : 'IDLE';

  return (
    <div className="status-bar">
      <div className="status-item"><span className={`status-dot ${dotClass}`} /><span className="status-val">SYSTEM {threatLevel === 'HIGH' ? 'ALERT' : 'NORMAL'}</span></div>
      <div className="status-separator" />
      <div className="status-item"><span className="status-label">Threat</span><span className={`status-val ${threatColor}`}>{threatLevel}</span></div>
      <div className="status-separator" />
      <div className="status-item"><span className="status-label">Alerts</span><span className={`status-val ${alertCount > 0 ? 'status-val-red' : ''}`}>{alertCount}</span></div>
      <div className="status-separator" />
      <span className={`capture-tag ${capClass}`}>{capText}</span>
      <div className="status-separator" />
      <div className="status-item"><span className="status-label">Updated</span><span className="status-val" style={{ color: 'var(--muted)', fontSize: '0.72rem', fontFamily: 'var(--mono)' }}>{timeStr}</span></div>
      <div style={{ flex: 1 }} />
      {!connected && <div className="status-item"><span className="status-dot status-dot-bad" /><span className="status-val status-val-red">OFFLINE</span></div>}
    </div>
  );
}
