import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ZAxis } from 'recharts';
import './CrossFlowCorrelation.css';

const API = 'http://localhost:8000';

export default function CrossFlowCorrelation() {
  const [correlations, setCorrelations] = useState([]);
  const [coordinatedAttacks, setCoordinatedAttacks] = useState([]);
  const [selectedCorrelation, setSelectedCorrelation] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${API}/cpp/cross-flow/correlations`);
      setCorrelations(res.data.correlations || []);
      setCoordinatedAttacks(res.data.coordinated_attacks || []);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch correlation data:', err);
      setLoading(false);
    }
  };

  const scatterData = correlations.map((corr, idx) => ({
    x: corr.temporal_overlap * 100,
    y: corr.correlation_score,
    z: corr.flow_count || 2,
    type: corr.correlation_type,
    flows: corr.correlated_flows
  }));

  if (loading) {
    return <div className="correlation-loading">Loading Cross-Flow Analysis...</div>;
  }

  return (
    <div className="cross-flow-correlation">
      <div className="correlation-header">
        <h2>Cross-Flow Correlation Analysis</h2>
        <div className="correlation-stats">
          <div className="stat-card">
            <span className="stat-label">Correlations Found</span>
            <span className="stat-value">{correlations.length}</span>
          </div>
          <div className="stat-card alert">
            <span className="stat-label">Coordinated Attacks</span>
            <span className="stat-value">{coordinatedAttacks.length}</span>
          </div>
        </div>
      </div>

      <div className="correlation-grid">
        <div className="correlation-card scatter-plot">
          <h3>Correlation Scatter Plot</h3>
          <p className="chart-description">Temporal Overlap vs Correlation Score</p>
          <ResponsiveContainer width="100%" height={400}>
            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis 
                type="number" 
                dataKey="x" 
                name="Temporal Overlap" 
                unit="%" 
                stroke="#94a3b8"
                label={{ value: 'Temporal Overlap (%)', position: 'insideBottom', offset: -10, fill: '#94a3b8' }}
              />
              <YAxis 
                type="number" 
                dataKey="y" 
                name="Score" 
                stroke="#94a3b8"
                label={{ value: 'Correlation Score', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
              />
              <ZAxis type="number" dataKey="z" range={[50, 400]} />
              <Tooltip 
                cursor={{ strokeDasharray: '3 3' }}
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="custom-tooltip">
                        <p><strong>Type:</strong> {data.type}</p>
                        <p><strong>Overlap:</strong> {data.x.toFixed(1)}%</p>
                        <p><strong>Score:</strong> {data.y.toFixed(2)}</p>
                        <p><strong>Flows:</strong> {data.z}</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Scatter 
                name="Correlations" 
                data={scatterData} 
                fill="#3b82f6"
                onClick={(data) => setSelectedCorrelation(data)}
              />
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        <div className="correlation-card coordinated-attacks">
          <h3>Coordinated Attack Detections</h3>
          <div className="attack-list">
            {coordinatedAttacks.length === 0 ? (
              <p className="no-data">No coordinated attacks detected</p>
            ) : (
              coordinatedAttacks.map((attack, idx) => (
                <div key={idx} className="attack-item">
                  <div className="attack-header">
                    <span className="attack-badge">COORDINATED ATTACK</span>
                    <span className="timestamp">{new Date(attack.timestamp * 1000).toLocaleTimeString()}</span>
                  </div>
                  <div className="attack-details">
                    <div className="detail-row">
                      <span className="label">Source IP:</span>
                      <span className="value">{attack.source_ip}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Protocols:</span>
                      <span className="value">{attack.protocols.join(', ')}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Flow Count:</span>
                      <span className="value">{attack.flow_count}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Correlation Score:</span>
                      <span className="value score">{attack.correlation_score.toFixed(2)}</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="correlation-card correlation-table">
          <h3>Correlation Details</h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Flow IDs</th>
                  <th>Type</th>
                  <th>Temporal Overlap</th>
                  <th>Score</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {correlations.slice(0, 20).map((corr, idx) => (
                  <tr 
                    key={idx}
                    className={selectedCorrelation?.flows === corr.correlated_flows ? 'selected' : ''}
                    onClick={() => setSelectedCorrelation(corr)}
                  >
                    <td className="flow-ids">
                      {corr.correlated_flows.slice(0, 2).join(', ')}
                      {corr.correlated_flows.length > 2 && ` +${corr.correlated_flows.length - 2}`}
                    </td>
                    <td>
                      <span className={`type-badge ${corr.correlation_type}`}>
                        {corr.correlation_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td>
                      <div className="progress-bar">
                        <div 
                          className="progress-fill" 
                          style={{ width: `${corr.temporal_overlap * 100}%` }}
                        />
                        <span>{(corr.temporal_overlap * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="score-cell">{corr.correlation_score.toFixed(2)}</td>
                    <td>{new Date(corr.timestamp * 1000).toLocaleTimeString()}</td>
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
