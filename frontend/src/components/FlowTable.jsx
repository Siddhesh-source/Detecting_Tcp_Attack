import React, { useState, useMemo } from 'react';

export default function FlowTable({ flows, onSelect, selectedFlowId }) {
  const [sortKey, setSortKey] = useState('suspicion_score');
  const [sortDir, setSortDir] = useState('desc');
  const [filter, setFilter] = useState('all');

  const handleSort = (k) => { if (sortKey === k) setSortDir(d => d === 'asc' ? 'desc' : 'asc'); else { setSortKey(k); setSortDir('desc'); } };

  const sorted = useMemo(() => {
    let f = [...(flows || [])];
    if (filter === 'suspicious') f = f.filter(x => (x.suspicion_score || 0) >= 40);
    else if (filter === 'long') f = f.filter(x => (x.duration || 0) > 60);
    f.sort((a, b) => { const va = a[sortKey] ?? 0; const vb = b[sortKey] ?? 0; return sortDir === 'asc' ? (va > vb ? 1 : -1) : (va < vb ? 1 : -1); });
    return f;
  }, [flows, sortKey, sortDir, filter]);

  const SI = ({ col }) => <span className={`sort-icon ${sortKey === col ? 'active' : ''}`}>{sortKey === col ? (sortDir === 'asc' ? '▲' : '▼') : '⬧'}</span>;
  const TH = ({ col, children }) => <th onClick={() => handleSort(col)}>{children} <SI col={col} /></th>;

  if (!flows?.length) return <div className="table-wrap"><div className="table-scroll"><div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}>No flows captured yet</div></div></div>;

  return (
    <>
      <div className="flow-header">
        <h2>Flows ({sorted.length})</h2>
        <div className="flow-filters">
          {[['all', 'All'], ['suspicious', 'Suspicious'], ['long', 'Long >60s']].map(([k, l]) => (
            <button key={k} onClick={() => setFilter(k)} className={`flow-filter-btn ${filter === k ? 'active' : ''}`}>{l}</button>
          ))}
        </div>
      </div>
      <div className="table-wrap">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <TH col="flow_id">Flow</TH>
                <TH col="src_ip">Src</TH>
                <TH col="dst_ip">Dst</TH>
                <TH col="dst_port">Port</TH>
                <TH col="duration">Dur</TH>
                <TH col="packets_per_sec">Pkts/s</TH>
                <TH col="std_iat">IATσ</TH>
                <TH col="suspicion_score">Score</TH>
                <TH col="predicted_label">Status</TH>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f, i) => {
                const s = f.suspicion_score ?? 0;
                const cls = s >= 70 ? 'score-high' : s >= 40 ? 'score-med' : 'score-low';
                return (
                  <tr key={i} className={`${f.predicted_label === 'ATTACK' ? 'row-alert' : ''} ${f.flow_id === selectedFlowId ? 'row-selected' : ''}`} onClick={() => onSelect(f)}>
                    <td className="td-trunc" title={f.flow_id}>{f.flow_id}</td>
                    <td>{f.src_ip}</td>
                    <td>{f.dst_ip}</td>
                    <td>{f.dst_port}</td>
                    <td>{f.duration?.toFixed(1)}s</td>
                    <td>{f.packets_per_sec?.toFixed(1)}</td>
                    <td>{f.std_iat?.toFixed(5)}</td>
                    <td className={cls}>{s.toFixed(0)}</td>
                    <td>{f.predicted_label === 'ATTACK' ? <span style={{ color: 'var(--red)', fontWeight: 800 }}>ALERT</span> : <span style={{ color: '#1e2e28' }}>OK</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
