import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import axios from 'axios';
import GlobalStatus from './components/GlobalStatus';
import AlertSummary from './components/AlertSummary';
import AnalyticsSection from './components/AnalyticsSection';
import FlowTable from './components/FlowTable';
import FlowDetailPanel from './components/FlowDetailPanel';
import Controls from './components/Controls';
import StoryBanner from './components/StoryBanner';
import ImbalanceBanner from './components/ImbalanceBanner';
import './App.css';

const API = 'http://localhost:8000';

export default function App() {
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [metrics, setMetrics] = useState({});
  const [featureImportance, setFeatureImportance] = useState([]);
  const [layerStats, setLayerStats] = useState({});
  const [connected, setConnected] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [captureIface, setCaptureIface] = useState('');
  const [threshold, setThreshold] = useState(50);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(Date.now());
  const [stories, setStories] = useState([]);
  const wsRef = useRef(null);
  const scoreHistoryRef = useRef([]);

  // ---- WebSocket -------------------------------------------------------
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(`ws://localhost:8000/ws/flows`);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        const flow = JSON.parse(e.data);
        setFlows(prev => [flow, ...prev].slice(0, 500));
        scoreHistoryRef.current = [...scoreHistoryRef.current.slice(-199), { time: Date.now(), score: flow.suspicion_score || 0 }];
        if (flow.is_anomaly === 1) {
          setAlerts(prev => [flow, ...prev].slice(0, 200));
          addStory(flow);
        }
        setLastUpdate(Date.now());
      };
      wsRef.current = ws;
    };
    connect();
    return () => wsRef.current?.close();
  }, []);

  const addStory = useCallback((flow) => {
    setStories(prev => [{
      id: Date.now(),
      text: `Anomaly detected: ${flow.src_ip} → ${flow.dst_ip}:${flow.dst_port} (score ${flow.suspicion_score?.toFixed(0)})`,
      time: new Date().toLocaleTimeString(),
    }, ...prev].slice(0, 5));
  }, []);

  // ---- Initial fetches -------------------------------------------------
  useEffect(() => {
    axios.get(`${API}/metrics`).then(r => setMetrics(r.data)).catch(() => {});
    axios.get(`${API}/features/importance`).then(r => setFeatureImportance(r.data.features || [])).catch(() => {});
    axios.get(`${API}/layers/stats`).then(r => setLayerStats(r.data)).catch(() => {});
    axios.get(`${API}/flows?limit=200`).then(r => setFlows(r.data.flows || []));
    axios.get(`${API}/alerts?threshold=${threshold}`).then(r => setAlerts(r.data.alerts || []));
    axios.get(`${API}/stats`).then(r => setStats(r.data));
  }, []);

  // ---- Poll /stats every 10s ------------------------------------------
  useEffect(() => {
    const iv = setInterval(() => {
      axios.get(`${API}/stats`).then(r => setStats(r.data)).catch(() => {});
      axios.get(`${API}/layers/stats`).then(r => setLayerStats(r.data)).catch(() => {});
    }, 10000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    axios.get(`${API}/alerts?threshold=${threshold}`).then(r => setAlerts(r.data.alerts || []));
  }, [threshold]);

  const refreshAll = useCallback(() => {
    axios.get(`${API}/flows?limit=200`).then(r => setFlows(r.data.flows || []));
    axios.get(`${API}/alerts?threshold=${threshold}`).then(r => setAlerts(r.data.alerts || []));
    axios.get(`${API}/stats`).then(r => setStats(r.data));
  }, [threshold]);

  const refreshMetrics = useCallback(() => {
    axios.get(`${API}/metrics`).then(r => setMetrics(r.data)).catch(() => {});
    axios.get(`${API}/features/importance`).then(r => setFeatureImportance(r.data.features || [])).catch(() => {});
    axios.get(`${API}/layers/stats`).then(r => setLayerStats(r.data)).catch(() => {});
  }, []);

  // ---- Computed --------------------------------------------------------
  const flowAnalytics = useMemo(() => {
    if (!flows.length) return {};
    const attackCount = flows.filter(f => f.predicted_label === 'ATTACK').length;
    const topPorts = {};
    flows.forEach(f => { const p = f.dst_port; topPorts[p] = (topPorts[p] || 0) + 1; });
    return { attackCount, topPorts: Object.entries(topPorts).sort((a, b) => b[1] - a[1]).slice(0, 8) };
  }, [flows]);

  const threatLevel = useMemo(() => {
    const n = alerts.length;
    if (n > 10) return 'HIGH';
    if (n > 0) return 'MEDIUM';
    return 'LOW';
  }, [alerts.length]);

  return (
    <div className={`app ${selectedFlow ? 'app--inspecting' : ''}`}>
      {/* ═══ LAYER 1: GLOBAL STATUS ═══ */}
      <GlobalStatus
        connected={connected}
        threatLevel={threatLevel}
        alertCount={alerts.length}
        capturing={capturing}
        captureIface={captureIface}
        lastUpdate={lastUpdate}
      />

      {/* ═══ STORY BANNER ═══ */}
      <StoryBanner stories={stories} />

      {/* ═══ IMBALANCE WARNING ═══ */}
      <ImbalanceBanner metrics={metrics} />

      {/* ═══ LAYER 2: ALERTS + SUMMARY ═══ */}
      <section className="layer layer--decision">
        <AlertSummary
          alerts={alerts}
          stats={stats}
          metrics={metrics}
          featureImportance={featureImportance}
          layerStats={layerStats}
          onSelectFlow={setSelectedFlow}
        />
      </section>

      {/* ═══ CONTROLS ═══ */}
      <Controls
        threshold={threshold}
        onThresholdChange={setThreshold}
        onRefresh={refreshAll}
        onRefreshMetrics={refreshMetrics}
        onStartCapture={async (iface) => { await axios.post(`${API}/capture/start`, { interface: iface }); setCapturing(true); setCaptureIface(iface); }}
        onStopCapture={async () => { await axios.post(`${API}/capture/stop`); setCapturing(false); setCaptureIface(''); }}
        capturing={capturing}
        flaggingPct={flows.length ? ((alerts.length / flows.length) * 100).toFixed(1) : '0.0'}
      />

      {/* ═══ LAYER 3: ANALYTICS ═══ */}
      <section className="layer layer--analytics">
        <AnalyticsSection
          flows={flows}
          layerStats={layerStats}
          flowAnalytics={flowAnalytics}
          featureImportance={featureImportance}
          scoreHistory={scoreHistoryRef.current}
          threshold={threshold}
          metrics={metrics}
        />
      </section>

      {/* ═══ LAYER 4: FLOW TABLE ═══ */}
      <section className="layer layer--deepdive">
        <FlowTable flows={flows} onSelect={setSelectedFlow} selectedFlowId={selectedFlow?.flow_id} />
      </section>

      {/* ═══ DETAIL PANEL (slides in from right) ═══ */}
      {selectedFlow && (
        <FlowDetailPanel flow={selectedFlow} onClose={() => setSelectedFlow(null)} />
      )}
    </div>
  );
}
