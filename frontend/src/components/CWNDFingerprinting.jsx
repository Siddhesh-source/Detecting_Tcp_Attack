import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import './CWNDFingerprinting.css';

const API = 'http://localhost:8000';

const ALGORITHM_COLORS = {
  RENO: '#3b82f6',
  CUBIC: '#10b981',
  BBR: '#f59e0b',
  VEGAS: '#8b5cf6',
  UNKNOWN: '#6b7280'
};

export default function CWNDFingerprinting() {
  const [fingerprints, setFingerprints] = useState([]);
  const [algorithmStats, setAlgorithmStats] = useState([]);
  const [switchingDetections, setSwitchingDetections] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [fpRes, statsRes] = await Promise.all([
        axios.get(`${API}/cpp/cwnd/fingerprints`),
        axios.get(`${API}/cpp/cwnd/algorithm-stats`)
      ]);
      
      setFingerprints(fpRes.data.fingerprints || []);
      setAlgorithmStats(fpRes.data.algorithm_distribution || []);
      setSwitchingDetections(fpRes.data.switching_detections || []);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch CWND data:', err);
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="cwnd-loading">Loading CWND Fingerprinting...</div>;
  }

  return (
    <div className="cwnd-fingerprinting">
      <div className="cwnd-header">
        <h2>TCP Congestion Control Algorithm Fingerprinting</h2>
        <div className="cwnd-stats">
          <div className="stat-card">
            <span className="stat-label">Total Flows</span>
            <span className="stat-value">{fingerprints.length}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Algorithm Switches</span>
            <span className="stat-value alert">{switchingDetections.length}</span>
          </div>
        </div>
      </div>

      <div className="cwnd-grid">
        <div className="cwnd-card algorithm-distribution">
          <h3>Algorithm Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={algorithmStats}
                dataKey="count"
                nameKey="algorithm"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label={({ algorithm, count }) => `${algorithm}: ${count}`}
              >
                {algorithmStats.map((entry, index) => (
                  <Cell key={index} fill={ALGORITHM_COLORS[entry.algorithm] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="cwnd-card switching-alerts">
          <h3>Algorithm Switching Detections</h3>
          <div className="switching-list">
            {switchingDetections.length === 0 ? (
              <p className="no-data">No algorithm switching detected</p>
            ) : (
              switchingDetections.map((detection, idx) => (
                <div key={idx} className="switching-item">
                  <div className="switching-header">
                    <span className="flow-id">{detection.flow_id}</span>
                    <span className="timestamp">{new Date(detection.timestamp * 1000).toLocaleTimeString()}</span>
                  </div>
                  <div className="switching-details">
                    <span className="algo-badge" style={{ backgroundColor: ALGORITHM_COLORS[detection.from_algorithm] }}>
                      {detection.from_algorithm}
                    </span>
                    <span className="arrow">→</span>
                    <span className="algo-badge" style={{ backgroundColor: ALGORITHM_COLORS[detection.to_algorithm] }}>
                      {detection.to_algorithm}
                    </span>
                    <span className="confidence">Confidence: {(detection.confidence * 100).toFixed(1)}%</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="cwnd-card fingerprint-table">
          <h3>Recent Fingerprints</h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Algorithm</th>
                  <th>Confidence</th>
                  <th>Growth Rate</th>
                  <th>Loss Response</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {fingerprints.slice(0, 20).map((fp, idx) => (
                  <tr key={idx}>
                    <td className="flow-id-cell">{fp.flow_id}</td>
                    <td>
                      <span className="algo-badge" style={{ backgroundColor: ALGORITHM_COLORS[fp.algorithm] }}>
                        {fp.algorithm}
                      </span>
                    </td>
                    <td>
                      <div className="confidence-bar">
                        <div 
                          className="confidence-fill" 
                          style={{ width: `${fp.confidence * 100}%` }}
                        />
                        <span>{(fp.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td>{fp.growth_rate?.toFixed(3) || 'N/A'}</td>
                    <td>{fp.loss_response?.toFixed(3) || 'N/A'}</td>
                    <td>{new Date(fp.timestamp * 1000).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
