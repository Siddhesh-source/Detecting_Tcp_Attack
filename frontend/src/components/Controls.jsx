import React, { useRef } from 'react';
import axios from 'axios';
const API = 'http://localhost:8000';

export default function Controls({ threshold, onThresholdChange, onRefresh, onRefreshMetrics, onStartCapture, onStopCapture, capturing, flaggingPct }) {
  const [interface_, setInterface_] = React.useState('');
  const [interfaces, setInterfaces] = React.useState([]);
  const fileRef = useRef();

  React.useEffect(() => {
    axios.get(`${API}/capture/interfaces`).then(r => {
      const ifaces = r.data.interfaces || [];
      setInterfaces(ifaces);
      // Auto-select first interface with valid IP
      const active = ifaces.find(i => i.ip && i.ip !== 'No IP' && i.ip !== '127.0.0.1');
      if (active) setInterface_(active.name);
    }).catch(() => {});
  }, []);

  const uploadPcap = async () => { const file = fileRef.current.files[0]; if (!file) return; const form = new FormData(); form.append('file', file); try { await axios.post(`${API}/upload/pcap`, form); onRefresh(); } catch (e) { console.error(e); } };

  return (
    <div className="controls-bar">
      <div className="control-group">
        <label className="control-label">Threshold <strong style={{ color: threshold >= 70 ? 'var(--red)' : threshold >= 40 ? 'var(--yellow)' : 'var(--green)' }}>{threshold}</strong></label>
        <input type="range" min="0" max="100" value={threshold} onChange={e => onThresholdChange(Number(e.target.value))} className="threshold-slider" />
      </div>
      <span style={{ fontSize: '0.65rem', color: 'var(--muted)', fontFamily: 'var(--mono)' }}>{flaggingPct}% flows flagged</span>
      <div className="controls-sep" />
      {!capturing ? (
        <>
          <select value={interface_} onChange={e => setInterface_(e.target.value)} className="interface-input">
            <option value="">Select interface...</option>
            {interfaces.map(i => (
              <option key={i.name} value={i.name}>{i.ip !== 'No IP' ? `${i.ip}` : i.name.slice(-20)}</option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={() => onStartCapture(interface_)} disabled={!interface_}>▶ Capture</button>
        </>
      ) : (
        <button className="btn btn-danger" onClick={onStopCapture}>■ Stop</button>
      )}
      <input type="file" accept=".pcap,.pcapng" ref={fileRef} style={{ display: 'none' }} onChange={uploadPcap} />
      <button className="btn" onClick={() => fileRef.current.click()}>📂 PCAP</button>
      <div className="controls-sep" />
      <button className="btn" onClick={onRefreshMetrics}>🧠 Retrain</button>
      <button className="btn" onClick={onRefresh}>↻</button>
    </div>
  );
}
