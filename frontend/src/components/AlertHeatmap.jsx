import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './AlertHeatmap.css';

const API = 'http://localhost:8000';

export default function AlertHeatmap() {
  const [heatmapData, setHeatmapData] = useState([]);
  const [protocolDist, setProtocolDist] = useState([]);
  const [geoData, setGeoData] = useState([]);
  const [timeRange, setTimeRange] = useState('24h');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${API}/alerts/heatmap?range=${timeRange}`);
      setHeatmapData(res.data.heatmap || []);
      setProtocolDist(res.data.protocol_distribution || []);
      setGeoData(res.data.geo_distribution || []);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch heatmap data:', err);
      setLoading(false);
    }
  };

  const hours = Array.from({ length: 24 }, (_, i) => i);
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  const getColor = (value) => {
    if (value === 0) return '#1e293b';
    if (value < 5) return '#3b82f6';
    if (value < 10) return '#f59e0b';
    return '#ef4444';
  };

  if (loading) {
    return <div className="heatmap-loading">Loading Alert Heatmap...</div>;
  }

  return (
    <div className="alert-heatmap">
      <div className="heatmap-header">
        <h2>Alert Severity Heatmap</h2>
        <div className="time-range-selector">
          {['24h', '7d', '30d'].map(range => (
            <button
              key={range}
              className={`range-btn ${timeRange === range ? 'active' : ''}`}
              onClick={() => setTimeRange(range)}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      <div className="heatmap-grid">
        <div className="heatmap-card time-heatmap">
          <h3>Alerts by Time</h3>
          <div className="heatmap-matrix">
            <div className="heatmap-y-axis">
              {days.map(day => (
                <div key={day} className="axis-label">{day}</div>
              ))}
            </div>
            <div className="heatmap-cells">
              {days.map((day, dayIdx) => (
                <div key={day} className="heatmap-row">
                  {hours.map(hour => {
                    const cell = heatmapData.find(d => d.day === dayIdx && d.hour === hour);
                    const value = cell?.count || 0;
                    return (
                      <div
                        key={hour}
                        className="heatmap-cell"
                        style={{ background: getColor(value) }}
                        title={`${day} ${hour}:00 - ${value} alerts`}
                      >
                        {value > 0 && <span>{value}</span>}
                      </div>
                    );
                  })}
                </div>
              ))}
              <div className="heatmap-x-axis">
                {[0, 6, 12, 18, 23].map(h => (
                  <div key={h} className="axis-label">{h}h</div>
                ))}
              </div>
            </div>
          </div>
          <div className="heatmap-legend">
            <span>Low</span>
            <div className="legend-gradient" />
            <span>High</span>
          </div>
        </div>

        <div className="heatmap-card protocol-pie">
          <h3>Protocol Distribution</h3>
          <div className="pie-container">
            {protocolDist.map((proto, idx) => {
              const colors = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ef4444'];
              return (
                <div key={idx} className="pie-item">
                  <div className="pie-color" style={{ background: colors[idx % colors.length] }} />
                  <span className="pie-label">{proto.protocol}</span>
                  <span className="pie-value">{proto.count}</span>
                  <span className="pie-percent">{proto.percentage.toFixed(1)}%</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="heatmap-card geo-distribution">
          <h3>Geographic Distribution</h3>
          <div className="geo-list">
            {geoData.slice(0, 10).map((geo, idx) => (
              <div key={idx} className="geo-item">
                <div className="geo-rank">#{idx + 1}</div>
                <div className="geo-info">
                  <span className="geo-country">{geo.country || 'Unknown'}</span>
                  <span className="geo-ip">{geo.ip}</span>
                </div>
                <div className="geo-bar">
                  <div 
                    className="geo-bar-fill" 
                    style={{ width: `${(geo.count / geoData[0].count) * 100}%` }}
                  />
                  <span className="geo-count">{geo.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
