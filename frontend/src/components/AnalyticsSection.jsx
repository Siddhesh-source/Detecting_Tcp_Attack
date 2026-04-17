import React from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Tooltip, Legend, Filler } from 'chart.js';
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Tooltip, Legend, Filler);

const SC = { x: { ticks: { color: '#5c6284', font: { size: 9 } }, grid: { color: '#12141e' } }, y: { ticks: { color: '#5c6284', font: { size: 9 } }, grid: { color: '#1c2030' } } };
const TT = (t) => ({ display: true, text: t, color: '#5c6284', font: { size: 10, weight: 600 }, padding: { bottom: 6 } });
const hasData = (arr) => arr && arr.length > 0;

export default function AnalyticsSection({ flows, layerStats, flowAnalytics, featureImportance, scoreHistory, threshold, metrics }) {
  const last40 = (flows || []).slice(0, 40).reverse();

  return (
    <div className="analytics-section">
      {/* ── TRAFFIC ── */}
      <div className="analytics-row-label">Traffic</div>
      <div className="analytics-row analytics-row-2">
        <div className="chart-box">
          {hasData(last40) ? (
            <div style={{ height: 130 }}><Line data={{ labels: last40.map((_, i) => i + 1), datasets: [{ label: 'Pkts/s', data: last40.map(f => f.packets_per_sec || 0), borderColor: '#4488ff', backgroundColor: '#4488ff14', fill: true, tension: 0.4, pointRadius: 1, borderWidth: 2 }] }} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: TT('Packets/sec') }, scales: SC }} /></div>
          ) : <div className="chart-box-empty">No traffic data</div>}
        </div>
        <div className="chart-box">
          {hasData(last40) ? (
            <div style={{ height: 130 }}><Line data={{ labels: last40.map((_, i) => i + 1), datasets: [{ label: 'Bytes/s', data: last40.map(f => f.bytes_per_sec || 0), borderColor: '#00ff88', backgroundColor: '#00ff8814', fill: true, tension: 0.4, pointRadius: 1, borderWidth: 2 }] }} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: TT('Bytes/sec') }, scales: SC }} /></div>
          ) : <div className="chart-box-empty">No traffic data</div>}
        </div>
      </div>

      {/* ── FLOW BEHAVIOR ── */}
      <div className="analytics-row-label">Flow Behavior</div>
      <div className="analytics-row analytics-row-2">
        <div className="chart-box">
          {hasData(flows) ? (() => {
            const bk = [{ l: '<10s', a: 0, b: 10 }, { l: '10-30s', a: 10, b: 30 }, { l: '30-60s', a: 30, b: 60 }, { l: '1-2m', a: 60, b: 120 }, { l: '>2m', a: 120, b: Infinity }];
            return <div style={{ height: 130 }}><Bar data={{ labels: bk.map(b => b.l), datasets: [{ data: bk.map(b => flows.filter(f => f.duration >= b.a && f.duration < b.b).length), backgroundColor: '#aa44ff', borderRadius: 3, borderSkipped: false }] }} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: TT('Flow Duration') }, scales: { ...SC, x: { ...SC.x, grid: { display: false } } } }} /></div>;
          })() : <div className="chart-box-empty">No flow data</div>}
        </div>
        <div className="chart-box">
          {hasData(flows) ? (() => {
            const bk = [{ l: '<64B', a: 0, b: 64 }, { l: '64-128', a: 64, b: 128 }, { l: '128-512', a: 128, b: 512 }, { l: '512-1K', a: 512, b: 1024 }, { l: '>1K', a: 1024, b: Infinity }];
            return <div style={{ height: 130 }}><Bar data={{ labels: bk.map(b => b.l), datasets: [{ data: bk.map(b => flows.filter(f => f.mean_pkt_size >= b.a && f.mean_pkt_size < b.b).length), backgroundColor: bk.map((b, i) => i === 0 ? '#ff444488' : '#4488ff'), borderRadius: 3, borderSkipped: false }] }} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: TT('Packet Size — ⚠ <100 = suspicious') }, scales: { ...SC, x: { ...SC.x, grid: { display: false } } } }} /></div>;
          })() : <div className="chart-box-empty">No flow data</div>}
        </div>
      </div>

      {/* ── DETECTION INSIGHTS ── */}
      <div className="analytics-row-label">Detection Insights</div>
      <div className="analytics-row analytics-row-3">
        <div className="chart-box">
          {hasData(flows) ? (() => {
            const bk = [{ l: '0', a: 0, b: 20 }, { l: '20-40', a: 20, b: 40 }, { l: '40-70', a: 40, b: 70 }, { l: '70-90', a: 70, b: 90 }, { l: '90+', a: 90, b: 101 }];
            return <div style={{ height: 130 }}><Bar data={{ labels: bk.map(b => b.l), datasets: [{ data: bk.map(b => flows.filter(f => f.suspicion_score >= b.a && f.suspicion_score < b.b).length), backgroundColor: ['#1e2e28', '#2a2e18', '#3a3018', '#3a1a1a', '#ff444488'], borderRadius: 3, borderSkipped: false }] }} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: TT('Score Distribution') }, scales: { ...SC, x: { ...SC.x, grid: { display: false } } } }} /></div>;
          })() : <div className="chart-box-empty">No data</div>}
        </div>
        <div className="chart-box">
          {featureImportance?.length > 0 ? (
            <div style={{ height: 130 }}>
              <Bar data={{ labels: featureImportance.slice(0, 6).map(f => f.feature), datasets: [{ data: featureImportance.slice(0, 6).map(f => f.importance), backgroundColor: featureImportance.slice(0, 6).map(f => ({ Transport: '#4488ff', Network: '#aa44ff', Derived: '#00ff88' }[f.layer] || '#888')), borderRadius: 3, borderSkipped: false }] }} options={{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: TT('Feature Importance') }, scales: { x: { ticks: { color: '#5c6284', font: { size: 8 } }, grid: { color: '#12141e' } }, y: { ticks: { color: '#e2e4ea', font: { size: 8, family: 'JetBrains Mono' } }, grid: { display: false } } } }} />
            </div>
          ) : <div className="chart-box-empty">No model data</div>}
        </div>
        <div className="chart-box">
          {(() => {
            const le = Object.entries(layerStats || {});
            return le.length > 0 ? (
              <div style={{ height: 130 }}><Doughnut data={{ labels: le.map(([k]) => k), datasets: [{ data: le.map(([, v]) => v), backgroundColor: le.map(([k]) => ({ Transport: '#4488ff', Network: '#aa44ff', Derived: '#00ff88' }[k] || '#888')), borderWidth: 0 }] }} options={{ responsive: true, maintainAspectRatio: false, cutout: '55%', plugins: { legend: { labels: { color: '#5c6284', font: { size: 9 } } }, title: TT('Alerts by Layer') } }} /></div>
            ) : <div className="chart-box-empty">No alerts yet</div>;
          })()}
        </div>
      </div>
    </div>
  );
}
