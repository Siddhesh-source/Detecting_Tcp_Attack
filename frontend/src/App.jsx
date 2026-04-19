import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import axios from 'axios';
import Sidebar from './components/Sidebar';
import DashboardView from './components/DashboardView';
import AlertsView from './components/AlertsView';
import NetworkTopology from './components/NetworkTopology';
import ShapExplainer from './components/ShapExplainer';
import BehavioralBaseline from './components/BehavioralBaseline';
import ThreatIntel from './components/ThreatIntel';
import FlowTable from './components/FlowTable';
import FlowDetailPanel from './components/FlowDetailPanel';
import './App.css';

const API = 'http://localhost:8000';

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
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

  const renderView = () => {
    const commonProps = {
      flows, alerts, stats, metrics, featureImportance, layerStats,
      connected, capturing, captureIface, threshold, setThreshold: setThreshold,
      lastUpdate, stories, scoreHistory: scoreHistoryRef.current,
      flowAnalytics, threatLevel, onRefresh: refreshAll,
      onRefreshMetrics: refreshMetrics,
      onStartCapture: async (iface) => {
        await axios.post(`${API}/capture/start`, { interface: iface });
        setCapturing(true);
        setCaptureIface(iface);
      },
      onStopCapture: async () => {
        await axios.post(`${API}/capture/stop`);
        setCapturing(false);
        setCaptureIface('');
      },
      onSelectFlow: setSelectedFlow
    };

    switch (activeView) {
      case 'dashboard':
        return <DashboardView {...commonProps} />;
      case 'alerts':
        return <AlertsView {...commonProps} />;
      case 'topology':
        return <NetworkTopology />;
      case 'explainability':
        return <ShapExplainer flows={flows} />;
      case 'baseline':
        return <BehavioralBaseline />;
      case 'threat-intel':
        return <ThreatIntel flows={flows} />;
      case 'flows':
        return <FlowTable flows={flows} onSelect={setSelectedFlow} selectedFlowId={selectedFlow?.flow_id} />;
      default:
        return <DashboardView {...commonProps} />;
    }
  };

  return (
    <>
      <Sidebar
        activeView={activeView}
        onViewChange={setActiveView}
        alertCount={alerts.length}
        connected={connected}
      />
      <div className="app-with-sidebar">
        <div className="main-content">
          {renderView()}
        </div>
      </div>
      {selectedFlow && (
        <FlowDetailPanel flow={selectedFlow} onClose={() => setSelectedFlow(null)} />
      )}
    </>
  );
}
