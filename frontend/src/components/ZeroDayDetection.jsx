import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import './ZeroDayDetection.css';

const API = 'http://localhost:8000';

export default function ZeroDayDetection() {
  const [novelPatterns, setNovelPatterns] = useState([]);
  const [anomalyScores, setAnomalyScores] = useState([]);
  const [detectionStats, setDetectionStats] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${API}/cpp/zero-day/detections`);
      setNovelPatterns(res.data.novel_patterns || []);
      setAnomalyScores(res.data.anomaly_scores || []);
      setDetectionStats(res.data.stats || {});
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch zero-day data:', err);
      setLoading(false);
    }
  };

  const scoreDistribution = anomalyScores.reduce((acc, score) => {
    const bucket = Math.floor(score.combined_score * 10) / 10;
    const existing = acc.find(item => item.score === bucket);
    if (existing) {
      existing.count++;
    } else {
      acc.push({ score: bucket, count: 1 });
    }
    return acc;
  }, []).sort((a, b) => a.score - b.score);

  if (loading) {
    return <div className="zeroday-loading">Loading Zero-Day Detection...</div>;
  }

  return (
    <div className="zero-day-detection">
      <div className="zeroday-header">
        <h2>Zero-Day Covert Channel Discovery</h2>
        <div className="zeroday-stats">
          <div className="stat-card">
            <span className="stat-label">Flows Analyzed</span>
            <span className="stat-value">{detectionStats.total_flows || 0}</span>
          </div>
          <div className="stat-card alert">
            <span className="stat-label">Novel Patterns</span>
            <span className="stat-value">{novelPatterns.length}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Avg Anomaly Score</span>
            <span className="stat-value">{(detectionStats.avg_score || 0).toFixed(3)}</span>
          </div>
        </div>
      </div>

      <div className="zeroday-grid">
        <div className="zeroday-card score-distribution">
          <h3>Anomaly Score Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={scoreDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis 
                dataKey="score" 
                stroke="#94a3b8"
                label={{ value: 'Anomaly Score', position: 'insideBottom', offset: -5, fill: '#94a3b8' }}
              />
              <YAxis 
                stroke="#94a3b8"
                label={{ value: 'Count', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
              />
              <Tooltip 
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#f1f5f9' }}
              />
              <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                {scoreDistribution.map((entry, index) => (
                  <Cell key={index} fill={entry.score > 0.7 ? '#ef4444' : entry.score > 0.5 ? '#f59e0b' : '#3b82f6'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="zeroday-card novel-patterns">
          <h3>Novel Pattern Detections</h3>
          <div className="pattern-list">
            {novelPatterns.length === 0 ? (
              <p className="no-data">No novel patterns detected</p>
            ) : (
              novelPatterns.map((pattern, idx) => (
                <div key={idx} className="pattern-item">
                  <div className="pattern-header">
                    <span className="pattern-badge">NOVEL PATTERN</span>
                    <span className="timestamp">{new Date(pattern.timestamp * 1000).toLocaleTimeString()}</span>
                  </div>
                  <div className="pattern-details">
                    <div className="detail-row">
                      <span className="label">Flow ID:</span>
                      <span className="value">{pattern.flow_id}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Isolation Score:</span>
                      <span className="value score">{pattern.isolation_score.toFixed(3)}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Autoencoder Score:</span>
                      <span className="value score">{pattern.autoencoder_score.toFixed(3)}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Combined Score:</span>
                      <span className="value score-high">{pattern.combined_score.toFixed(3)}</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="zeroday-card anomaly-table">
          <h3>Recent Anomaly Scores</h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Isolation</th>
                  <th>Autoencoder</th>
                  <th>Combined</th>
                  <th>Novel</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {anomalyScores.slice(0, 20).map((score, idx) => (
                  <tr key={idx} className={score.is_novel_pattern ? 'novel-row' : ''}>
                    <td className="flow-id-cell">{score.flow_id}</td>
                    <td>
                      <div className="score-bar">
                        <div 
                          className="score-fill isolation" 
                          style={{ width: `${score.isolation_score * 100}%` }}
                        />
                        <span>{score.isolation_score.toFixed(2)}</span>
                      </div>
                    </td>
                    <td>
                      <div className="score-bar">
                        <div 
                          className="score-fill autoencoder" 
                          style={{ width: `${Math.min(score.autoencoder_score, 1) * 100}%` }}
                        />
                        <span>{score.autoencoder_score.toFixed(2)}</span>
                      </div>
                    </td>
                    <td>
                      <div className="score-bar">
                        <div 
                          className="score-fill combined" 
                          style={{ width: `${score.combined_score * 100}%` }}
                        />
                        <span>{score.combined_score.toFixed(2)}</span>
                      </div>
                    </td>
                    <td>
                      {score.is_novel_pattern ? (
                        <span className="badge novel">YES</span>
                      ) : (
                        <span className="badge normal">NO</span>
                      )}
                    </td>
                    <td>{new Date(score.timestamp * 1000).toLocaleTimeString()}</td>
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
