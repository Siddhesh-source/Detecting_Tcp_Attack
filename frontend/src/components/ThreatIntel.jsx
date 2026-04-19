import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { FiShield, FiGlobe, FiAlertTriangle, FiCheckCircle } from 'react-icons/fi';
import './ThreatIntel.css';

const API = 'http://localhost:8000';

export default function ThreatIntel({ flows }) {
  const [threatStats, setThreatStats] = useState({});
  const [selectedIP, setSelectedIP] = useState(null);
  const [ipReputation, setIPReputation] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchThreatStats();
    const interval = setInterval(fetchThreatStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchThreatStats = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/stats`);
      setThreatStats(res.data);
    } catch (err) {
      console.error('Threat intel stats error:', err);
    }
  };

  const lookupIP = async (ip) => {
    setLoading(true);
    setSelectedIP(ip);
    try {
      const res = await axios.get(`${API}/threat-intel/lookup/${ip}`);
      setIPReputation(res.data);
    } catch (err) {
      console.error('IP lookup error:', err);
    }
    setLoading(false);
  };

  const uniqueIPs = [...new Set(flows.map(f => f.src_ip))].slice(0, 20);

  return (
    <div className="threat-intel">
      <div className="threat-header">
        <h2><FiShield /> Threat Intelligence</h2>
        <div className="threat-stats">
          <div className="stat-badge">
            <FiGlobe />
            <span>{threatStats.cached_ips || 0} Cached IPs</span>
          </div>
          <div className="stat-badge alert">
            <FiAlertTriangle />
            <span>{threatStats.known_malicious || 0} Known Threats</span>
          </div>
        </div>
      </div>

      <div className="threat-content">
        <div className="ip-lookup-panel">
          <h3>IP Reputation Lookup</h3>
          <div className="ip-selector">
            <select value={selectedIP || ''} onChange={(e) => lookupIP(e.target.value)}>
              <option value="">Select IP to lookup...</option>
              {uniqueIPs.map(ip => (
                <option key={ip} value={ip}>{ip}</option>
              ))}
            </select>
          </div>

          {loading && <div className="threat-loading">Looking up IP reputation...</div>}

          {!loading && ipReputation && (
            <motion.div
              className="reputation-card"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="reputation-header">
                <div className="ip-display">{ipReputation.ip}</div>
                <div className={`threat-badge ${ipReputation.is_malicious ? 'malicious' : 'clean'}`}>
                  {ipReputation.is_malicious ? (
                    <><FiAlertTriangle /> MALICIOUS</>
                  ) : (
                    <><FiCheckCircle /> CLEAN</>
                  )}
                </div>
              </div>

              <div className="reputation-score">
                <div className="score-label">Reputation Score</div>
                <div className="score-value">{ipReputation.reputation_score}/100</div>
                <div className="score-bar">
                  <div
                    className={`score-fill ${ipReputation.reputation_score > 50 ? 'high' : 'low'}`}
                    style={{ width: `${ipReputation.reputation_score}%` }}
                  />
                </div>
              </div>

              {ipReputation.threat_types?.length > 0 && (
                <div className="threat-types">
                  <div className="section-label">Threat Types</div>
                  <div className="threat-tags">
                    {ipReputation.threat_types.map(type => (
                      <span key={type} className="threat-tag">{type}</span>
                    ))}
                  </div>
                </div>
              )}

              {ipReputation.sources?.length > 0 && (
                <div className="threat-sources">
                  <div className="section-label">Intelligence Sources</div>
                  <div className="source-list">
                    {ipReputation.sources.map(source => (
                      <div key={source} className="source-item">{source}</div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {!loading && !ipReputation && (
            <div className="threat-empty">
              <FiShield size={48} />
              <p>Select an IP to check reputation</p>
            </div>
          )}
        </div>

        <div className="threat-summary">
          <h3>Recent Threat Activity</h3>
          <div className="threat-timeline">
            {flows.filter(f => f.is_anomaly === 1).slice(0, 10).map((flow, idx) => (
              <motion.div
                key={flow.flow_id}
                className="timeline-item"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.05 }}
                onClick={() => lookupIP(flow.src_ip)}
              >
                <div className="timeline-time">
                  {new Date(flow.created_at * 1000).toLocaleTimeString()}
                </div>
                <div className="timeline-content">
                  <div className="timeline-ip">{flow.src_ip} → {flow.dst_ip}</div>
                  <div className="timeline-score">Score: {flow.suspicion_score?.toFixed(0)}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
