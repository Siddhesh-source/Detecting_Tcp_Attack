import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import './PerformanceMetrics.css';

const API = 'http://localhost:8000';

export default function PerformanceMetrics() {
  const [throughputData, setThroughputData] = useState([]);
  const [latencyData, setLatencyData] = useState([]);
  const [simdStats, setSimdStats] = useState({});
  const [engineStatus, setEngineStatus] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [perfRes, statusRes] = await Promise.all([
        axios.get(`${API}/cpp/performance/metrics`),
        axios.get(`${API}/cpp/status`)
      ]);
      
      setThroughputData(perfRes.data.throughput_history || []);
      setLatencyData(perfRes.data.latency_history || []);
      setSimdStats(perfRes.data.simd_stats || {});
      setEngineStatus(statusRes.data);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch performance data:', err);
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="performance-loading">Loading Performance Metrics...</div>;
  }

  return (
    <div className="performance-metrics">
      <div className="performance-header">
        <h2>Performance Metrics & Hardware Acceleration</h2>
        <div className="engine-status-badge">
          <span className={`status-dot ${engineStatus.available ? 'active' : 'inactive'}`} />
          <span>{engineStatus.available ? 'C++ Engine Active' : 'Python Fallback'}</span>
        </div>
      </div>

      <div className="performance-grid">
        <div className="performance-card throughput-chart">
          <h3>Packet Throughput</h3>
          <p className="chart-subtitle">Packets per second</p>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={throughputData.slice(-50)}>
              <defs>
                <linearGradient id="throughputGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="timestamp" stroke="#94a3b8" hide />
              <YAxis stroke="#94a3b8" />
              <Tooltip 
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#f1f5f9' }}
              />
              <Area 
                type="monotone" 
                dataKey="packets_per_sec" 
                stroke="#3b82f6" 
                fillOpacity={1} 
                fill="url(#throughputGradient)" 
              />
            </AreaChart>
          </ResponsiveContainer>
          <div className="metric-summary">
            <div className="metric-item">
              <span className="metric-label">Current</span>
              <span className="metric-value">{throughputData[throughputData.length - 1]?.packets_per_sec || 0} pps</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Peak</span>
              <span className="metric-value">{Math.max(...throughputData.map(d => d.packets_per_sec || 0))} pps</span>
            </div>
          </div>
        </div>

        <div className="performance-card latency-chart">
          <h3>Detection Latency</h3>
          <p className="chart-subtitle">Milliseconds per flow</p>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={latencyData.slice(-50)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="timestamp" stroke="#94a3b8" hide />
              <YAxis stroke="#94a3b8" />
              <Tooltip 
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#f1f5f9' }}
              />
              <Line 
                type="monotone" 
                dataKey="latency_ms" 
                stroke="#10b981" 
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
          <div className="metric-summary">
            <div className="metric-item">
              <span className="metric-label">Avg</span>
              <span className="metric-value">
                {(latencyData.reduce((sum, d) => sum + (d.latency_ms || 0), 0) / latencyData.length || 0).toFixed(2)} ms
              </span>
            </div>
            <div className="metric-item">
              <span className="metric-label">P99</span>
              <span className="metric-value">
                {latencyData.sort((a, b) => b.latency_ms - a.latency_ms)[Math.floor(latencyData.length * 0.01)]?.latency_ms.toFixed(2) || 0} ms
              </span>
            </div>
          </div>
        </div>

        <div className="performance-card simd-stats">
          <h3>SIMD Acceleration Stats</h3>
          <div className="stats-grid">
            <div className="stat-item">
              <span className="stat-icon">⚡</span>
              <div className="stat-content">
                <span className="stat-label">Speedup Factor</span>
                <span className="stat-value">{simdStats.speedup_factor || 0}x</span>
              </div>
            </div>
            <div className="stat-item">
              <span className="stat-icon">🔢</span>
              <div className="stat-content">
                <span className="stat-label">SIMD Operations</span>
                <span className="stat-value">{simdStats.simd_operations || 0}</span>
              </div>
            </div>
            <div className="stat-item">
              <span className="stat-icon">📊</span>
              <div className="stat-content">
                <span className="stat-label">Entropy Calcs/sec</span>
                <span className="stat-value">{simdStats.entropy_per_sec || 0}</span>
              </div>
            </div>
            <div className="stat-item">
              <span className="stat-icon">🔄</span>
              <div className="stat-content">
                <span className="stat-label">Autocorr Calcs/sec</span>
                <span className="stat-value">{simdStats.autocorr_per_sec || 0}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="performance-card detector-status">
          <h3>Active Detectors</h3>
          <div className="detector-list">
            {engineStatus.detectors && Object.entries(engineStatus.detectors).map(([name, active]) => (
              <div key={name} className="detector-item">
                <span className={`detector-dot ${active ? 'active' : 'inactive'}`} />
                <span className="detector-name">{name.replace('_', ' ')}</span>
                <span className={`detector-status ${active ? 'active' : 'inactive'}`}>
                  {active ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
