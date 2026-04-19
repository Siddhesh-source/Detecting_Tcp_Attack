import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { FiClock, FiActivity, FiTrendingUp, FiAlertCircle } from 'react-icons/fi';
import { Line } from 'react-chartjs-2';
import './BehavioralBaseline.css';

const API = 'http://localhost:8000';

export default function BehavioralBaseline() {
  const [baselineStats, setBaselineStats] = useState({});
  const [selectedIP, setSelectedIP] = useState(null);
  const [ipProfile, setIPProfile] = useState(null);
  const [circadianData, setCircadianData] = useState(null);

  useEffect(() => {
    fetchBaselineStats();
    const interval = setInterval(fetchBaselineStats, 20000);
    return () => clearInterval(interval);
  }, []);

  const fetchBaselineStats = async () => {
    try {
      const res = await axios.get(`${API}/baseline/stats`);
      setBaselineStats(res.data);
    } catch (err) {
      console.error('Baseline stats error:', err);
    }
  };

  const fetchIPProfile = async (ip) => {
    try {
      const [profile, circadian] = await Promise.all([
        axios.get(`${API}/baseline/profile/${ip}`),
        axios.get(`${API}/baseline/circadian/${ip}`)
      ]);
      setIPProfile(profile.data);
      setCircadianData(circadian.data);
      setSelectedIP(ip);
    } catch (err) {
      console.error('IP profile error:', err);
    }
  };

  const progress = baselineStats.learning_progress || 0;
  const isEstablished = baselineStats.baseline_established;

  return (
    <div className="behavioral-baseline">
      <div className="baseline-header">
        <h2><FiActivity /> Behavioral Baseline</h2>
        <div className="baseline-status">
          {isEstablished ? (
            <div className="status-badge established">
              <FiTrendingUp /> Baseline Established
            </div>
          ) : (
            <div className="status-badge learning">
              <FiClock /> Learning ({progress.toFixed(0)}%)
            </div>
          )}
        </div>
      </div>

      <div className="baseline-grid">
        <div className="baseline-card">
          <h3>Overview</h3>
          <div className="stats-grid">
            <div className="stat-item">
              <div className="stat-label">Total Profiles</div>
              <div className="stat-value">{baselineStats.total_profiles || 0}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Subnets</div>
              <div className="stat-value">{baselineStats.total_subnets || 0}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Learning Progress</div>
              <div className="progress-container">
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${progress}%` }} />
                </div>
                <span>{progress.toFixed(0)}%</span>
              </div>
            </div>
          </div>
        </div>

        <div className="baseline-card">
          <h3>Top Active IPs</h3>
          <div className="ip-list">
            {baselineStats.top_active_ips?.slice(0, 10).map(([ip, count], idx) => (
              <motion.div
                key={ip}
                className="ip-item"
                onClick={() => fetchIPProfile(ip)}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.03 }}
              >
                <div className="ip-rank">#{idx + 1}</div>
                <div className="ip-address">{ip}</div>
                <div className="ip-count">{count} flows</div>
              </motion.div>
            ))}
          </div>
        </div>

        {selectedIP && ipProfile && (
          <div className="baseline-card profile-detail">
            <h3>Profile: {selectedIP}</h3>
            <div className="profile-metrics">
              <div className="metric-row">
                <span>Total Flows:</span>
                <strong>{ipProfile.flow_count}</strong>
              </div>
              <div className="metric-row">
                <span>Total Bytes:</span>
                <strong>{(ipProfile.total_bytes / 1024).toFixed(2)} KB</strong>
              </div>
              <div className="metric-row">
                <span>Avg Duration:</span>
                <strong>{ipProfile.avg_duration?.toFixed(2)}s</strong>
              </div>
            </div>

            <h4>Protocols</h4>
            <div className="protocol-bars">
              {Object.entries(ipProfile.protocols || {}).map(([proto, count]) => {
                const total = Object.values(ipProfile.protocols).reduce((a, b) => a + b, 0);
                const pct = (count / total) * 100;
                return (
                  <div key={proto} className="protocol-bar">
                    <span>{proto}</span>
                    <div className="bar">
                      <div className="bar-fill" style={{ width: `${pct}%` }} />
                    </div>
                    <span>{count}</span>
                  </div>
                );
              })}
            </div>

            <h4>Top Ports</h4>
            <div className="port-list">
              {ipProfile.top_ports?.slice(0, 5).map(([port, count]) => (
                <div key={port} className="port-item">
                  <span className="port-number">{port}</span>
                  <span className="port-count">{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {circadianData && (
          <div className="baseline-card circadian-chart">
            <h3><FiClock /> Circadian Rhythm - {selectedIP}</h3>
            <Line
              data={{
                labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
                datasets: [{
                  label: 'Activity by Hour',
                  data: circadianData.hourly_activity,
                  borderColor: '#00d4ff',
                  backgroundColor: 'rgba(0, 212, 255, 0.1)',
                  fill: true,
                  tension: 0.4
                }]
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { display: false }
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#888' }
                  },
                  x: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#888' }
                  }
                }
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
