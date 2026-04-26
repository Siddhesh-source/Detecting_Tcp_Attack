import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Tooltip } from 'recharts';
import './ProtocolAgnostic.css';

const API = 'http://localhost:8000';

export default function ProtocolAgnostic() {
  const [protocolFeatures, setProtocolFeatures] = useState([]);
  const [similarityMatrix, setSimilarityMatrix] = useState([]);
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${API}/cpp/protocol-agnostic/analysis`);
      setProtocolFeatures(res.data.protocol_features || []);
      setSimilarityMatrix(res.data.similarity_matrix || []);
      setDetections(res.data.detections || []);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch protocol-agnostic data:', err);
      setLoading(false);
    }
  };

  const radarData = protocolFeatures.slice(0, 5).map(pf => ({
    protocol: pf.protocol,
    iat: pf.mean_iat * 100,
    size: pf.mean_size / 15,
    entropy: pf.entropy * 10,
    burst: pf.burst_ratio * 100
  }));

  if (loading) {
    return <div className="protocol-loading">Loading Protocol-Agnostic Analysis...</div>;
  }

  return (
    <div className="protocol-agnostic">
      <div className="protocol-header">
        <h2>Protocol-Agnostic Behavioral Analysis</h2>
        <div className="protocol-stats">
          <div className="stat-card">
            <span className="stat-label">Protocols Analyzed</span>
            <span className="stat-value">{new Set(protocolFeatures.map(p => p.protocol)).size}</span>
          </div>
          <div className="stat-card alert">
            <span className="stat-label">Detections</span>
            <span className="stat-value">{detections.length}</span>
          </div>
        </div>
      </div>

      <div className="protocol-grid">
        <div className="protocol-card radar-chart">
          <h3>Universal Feature Comparison</h3>
          <ResponsiveContainer width="100%" height={400}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="protocol" stroke="#94a3b8" />
              <PolarRadiusAxis stroke="#94a3b8" />
              <Radar name="Features" dataKey="iat" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.3} />
              <Radar name="Size" dataKey="size" stroke="#10b981" fill="#10b981" fillOpacity={0.3} />
              <Radar name="Entropy" dataKey="entropy" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.3} />
              <Radar name="Burst" dataKey="burst" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.3} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155' }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="protocol-card similarity-heatmap">
          <h3>Protocol Similarity Matrix</h3>
          <div className="heatmap-container">
            {similarityMatrix.map((row, i) => (
              <div key={i} className="heatmap-row">
                <span className="row-label">{row.protocol}</span>
                {row.similarities.map((sim, j) => (
                  <div 
                    key={j} 
                    className="heatmap-cell"
                    style={{ 
                      background: `rgba(59, 130, 246, ${sim})`,
                      color: sim > 0.5 ? 'white' : '#94a3b8'
                    }}
                    title={`${sim.toFixed(2)}`}
                  >
                    {sim.toFixed(1)}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>

        <div className="protocol-card detection-table">
          <h3>Covert Channel Detections</h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Protocol</th>
                  <th>IAT</th>
                  <th>Entropy</th>
                  <th>Burst Ratio</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {detections.slice(0, 20).map((det, idx) => (
                  <tr key={idx} className={det.is_covert ? 'covert-row' : ''}>
                    <td className="flow-id-cell">{det.flow_id}</td>
                    <td><span className="protocol-badge">{det.protocol}</span></td>
                    <td>{det.mean_iat.toFixed(4)}</td>
                    <td>{det.entropy.toFixed(2)}</td>
                    <td>{(det.burst_ratio * 100).toFixed(0)}%</td>
                    <td>
                      {det.is_covert ? (
                        <span className="badge covert">COVERT</span>
                      ) : (
                        <span className="badge normal">NORMAL</span>
                      )}
                    </td>
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
