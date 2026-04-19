import React, { useState } from 'react';
import { FiAlertTriangle, FiFilter, FiDownload } from 'react-icons/fi';
import axios from 'axios';
import './AlertsView.css';

const API = 'http://localhost:8000';

export default function AlertsView({ alerts, threshold, onThresholdChange, onSelectFlow }) {
  const [filter, setFilter] = useState('');
  const [sortBy, setSortBy] = useState('score');

  const filtered = alerts
    .filter(a => !filter || a.src_ip?.includes(filter) || a.dst_ip?.includes(filter) || a.protocol?.includes(filter.toUpperCase()))
    .sort((a, b) => sortBy === 'score' ? b.suspicion_score - a.suspicion_score : b.created_at - a.created_at);

  const getSeverity = (score) => {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
  };

  const exportAlerts = async () => {
    const res = await axios.get(`${API}/export/alerts?threshold=${threshold}`, { responseType: 'blob' });
    const url = window.URL.createObjectURL(res.data);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'alerts.csv';
    a.click();
  };

  return (
    <div className="alerts-view">
      <div className="alerts-header">
        <div className="alerts-title">
          <FiAlertTriangle />
          <h2>Alerts</h2>
          <span className="alert-count">{filtered.length}</span>
        </div>
        <div className="alerts-actions">
          <button className="action-btn" onClick={exportAlerts}>
            <FiDownload /> Export CSV
          </button>
        </div>
      </div>

      <div className="alerts-controls">
        <div className="filter-group">
          <FiFilter />
          <input
            type="text"
            placeholder="Filter by IP or protocol..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="filter-input"
          />
        </div>
        <div className="sort-group">
          <label>Sort by:</label>
          <select value={sortBy} onChange={e => setSortBy(e.target.value)} className="sort-select">
            <option value="score">Suspicion Score</option>
            <option value="time">Time</option>
          </select>
        </div>
        <div className="threshold-group">
          <label>Threshold: {threshold}</label>
          <input
            type="range" min={0} max={100} value={threshold}
            onChange={e => onThresholdChange(Number(e.target.value))}
            className="threshold-slider"
          />
        </div>
      </div>

      <div className="severity-summary">
        {['critical', 'high', 'medium'].map(sev => {
          const count = filtered.filter(a => getSeverity(a.suspicion_score) === sev).length;
          return (
            <div key={sev} className={`severity-chip ${sev}`}>
              <span className="severity-label">{sev.toUpperCase()}</span>
              <span className="severity-count">{count}</span>
            </div>
          );
        })}
      </div>

      <div className="alerts-list">
        {filtered.length === 0 && (
          <div className="alerts-empty">No alerts match your filters</div>
        )}
        {filtered.map((alert, idx) => {
          const sev = getSeverity(alert.suspicion_score);
          return (
            <div key={alert.flow_id || idx} className={`alert-card ${sev}`} onClick={() => onSelectFlow?.(alert)}>
              <div className="alert-severity-bar" />
              <div className="alert-body">
                <div className="alert-top">
                  <div className="alert-flow">
                    <span className="alert-ip">{alert.src_ip}</span>
                    <span className="alert-arrow">→</span>
                    <span className="alert-ip">{alert.dst_ip}:{alert.dst_port}</span>
                    <span className={`alert-proto ${alert.protocol?.toLowerCase()}`}>{alert.protocol}</span>
                  </div>
                  <div className="alert-score">{alert.suspicion_score?.toFixed(0)}</div>
                </div>
                <div className="alert-reasons">{alert.alert_reasons || '—'}</div>
                <div className="alert-meta">
                  <span>{new Date(alert.created_at * 1000).toLocaleTimeString()}</span>
                  <span>{alert.total_packets} pkts</span>
                  <span>{(alert.duration || 0).toFixed(1)}s</span>
                  <span className={`sev-badge ${sev}`}>{sev.toUpperCase()}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
