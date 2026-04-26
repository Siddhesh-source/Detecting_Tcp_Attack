import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import './AdversarialRobustness.css';

const API = 'http://localhost:8000';

export default function AdversarialRobustness() {
  const [robustnessScores, setRobustnessScores] = useState([]);
  const [adversarialDetections, setAdversarialDetections] = useState([]);
  const [sanitizationLogs, setSanitizationLogs] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${API}/cpp/adversarial/metrics`);
      setRobustnessScores(res.data.robustness_scores || []);
      setAdversarialDetections(res.data.adversarial_detections || []);
      setSanitizationLogs(res.data.sanitization_logs || []);
      setStats(res.data.stats || {});
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch adversarial data:', err);
      setLoading(false);
    }
  };

  const timeSeriesData = robustnessScores.slice(-50).map((score, idx) => ({
    index: idx,
    robustness: score.robustness_score,
    perturbation: score.perturbation_magnitude
  }));

  if (loading) {
    return <div className="adversarial-loading">Loading Adversarial Robustness...</div>;
  }

  return (
    <div className="adversarial-robustness">
      <div className="adversarial-header">
        <h2>Adversarial Robustness & Defense</h2>
        <div className="adversarial-stats">
          <div className="stat-card">
            <span className="stat-label">Avg Robustness</span>
            <span className="stat-value">{(stats.avg_robustness || 0).toFixed(3)}</span>
          </div>
          <div className="stat-card alert">
            <span className="stat-label">Attacks Detected</span>
            <span className="stat-value">{adversarialDetections.length}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Sanitizations</span>
            <span className="stat-value">{sanitizationLogs.length}</span>
          </div>
        </div>
      </div>

      <div className="adversarial-grid">
        <div className="adversarial-card robustness-chart">
          <h3>Robustness Score Timeline</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="index" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" domain={[0, 1]} />
              <Tooltip 
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#f1f5f9' }}
              />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="robustness" 
                stroke="#10b981" 
                strokeWidth={2}
                dot={false}
                name="Robustness Score"
              />
              <Line 
                type="monotone" 
                dataKey="perturbation" 
                stroke="#ef4444" 
                strokeWidth={2}
                dot={false}
                name="Perturbation Magnitude"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="adversarial-card attack-detections">
          <h3>Adversarial Attack Detections</h3>
          <div className="detection-list">
            {adversarialDetections.length === 0 ? (
              <p className="no-data">No adversarial attacks detected</p>
            ) : (
              adversarialDetections.map((detection, idx) => (
                <div key={idx} className="detection-item">
                  <div className="detection-header">
                    <span className="detection-badge">ADVERSARIAL ATTACK</span>
                    <span className="timestamp">{new Date(detection.timestamp * 1000).toLocaleTimeString()}</span>
                  </div>
                  <div className="detection-details">
                    <div className="detail-row">
                      <span className="label">Flow ID:</span>
                      <span className="value">{detection.flow_id}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Attack Type:</span>
                      <span className="value">{detection.attack_type}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Confidence:</span>
                      <span className="value score">{(detection.confidence * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="adversarial-card sanitization-logs">
          <h3>Input Sanitization Logs</h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Features Modified</th>
                  <th>Sanitization Type</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {sanitizationLogs.slice(0, 20).map((log, idx) => (
                  <tr key={idx}>
                    <td className="flow-id-cell">{log.flow_id}</td>
                    <td>{log.features_modified}</td>
                    <td>
                      <span className="sanitization-badge">{log.sanitization_type}</span>
                    </td>
                    <td>{new Date(log.timestamp * 1000).toLocaleTimeString()}</td>
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
