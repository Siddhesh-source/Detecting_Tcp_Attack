import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { FiActivity, FiAlertTriangle, FiCpu, FiDatabase, FiEye, FiLayers, FiShield, FiZap } from 'react-icons/fi';
import './NetworkTopology.css';

const API = 'http://localhost:8000';

export default function NetworkTopology() {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [], stats: {} });
  const [centrality, setCentrality] = useState({});
  const [topTalkers, setTopTalkers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTopologyData();
    const interval = setInterval(fetchTopologyData, 15000);
    return () => clearInterval(interval);
  }, []);

  const fetchTopologyData = async () => {
    try {
      const [graph, cent, talkers] = await Promise.all([
        axios.get(`${API}/topology/graph`),
        axios.get(`${API}/topology/centrality`),
        axios.get(`${API}/topology/top-talkers?limit=10`)
      ]);
      setGraphData(graph.data);
      setCentrality(cent.data.centrality || {});
      setTopTalkers(talkers.data.top_talkers || []);
      setLoading(false);
    } catch (err) {
      console.error('Topology fetch error:', err);
    }
  };

  if (loading) {
    return <div className="topology-loading">Loading network topology...</div>;
  }

  return (
    <div className="network-topology">
      <div className="topology-header">
        <h2><FiActivity /> Network Topology</h2>
        <div className="topology-stats">
          <div className="stat-badge">
            <FiDatabase />
            <span>{graphData.stats.total_nodes || 0} Nodes</span>
          </div>
          <div className="stat-badge">
            <FiLayers />
            <span>{graphData.stats.total_edges || 0} Connections</span>
          </div>
          <div className="stat-badge alert">
            <FiAlertTriangle />
            <span>{graphData.stats.suspicious_nodes || 0} Suspicious</span>
          </div>
          <div className="stat-badge">
            <FiCpu />
            <span>{graphData.stats.communities || 0} Communities</span>
          </div>
        </div>
      </div>

      <div className="topology-content">
        <div className="topology-viz">
          <NetworkGraph nodes={graphData.nodes} edges={graphData.edges} />
        </div>

        <div className="topology-sidebar">
          <div className="topology-panel">
            <h3><FiZap /> Top Talkers</h3>
            <div className="top-talkers-list">
              {topTalkers.map((talker, idx) => (
                <motion.div
                  key={talker.ip}
                  className={`talker-item ${talker.is_suspicious ? 'suspicious' : ''}`}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.05 }}
                >
                  <div className="talker-rank">#{idx + 1}</div>
                  <div className="talker-info">
                    <div className="talker-ip">{talker.ip}</div>
                    <div className="talker-flows">{talker.flow_count} flows</div>
                  </div>
                  {talker.is_suspicious && <FiShield className="suspicious-icon" />}
                </motion.div>
              ))}
            </div>
          </div>

          <div className="topology-panel">
            <h3><FiEye /> Centrality Metrics</h3>
            <div className="centrality-list">
              {Object.entries(centrality).slice(0, 5).map(([ip, metrics]) => (
                <div key={ip} className="centrality-item">
                  <div className="centrality-ip">{ip}</div>
                  <div className="centrality-metrics">
                    <div className="metric-bar">
                      <span>Degree</span>
                      <div className="bar">
                        <div className="bar-fill" style={{ width: `${metrics.degree_centrality * 100}%` }} />
                      </div>
                    </div>
                    <div className="metric-bar">
                      <span>Betweenness</span>
                      <div className="bar">
                        <div className="bar-fill" style={{ width: `${metrics.betweenness_centrality * 100}%` }} />
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function NetworkGraph({ nodes, edges }) {
  const [positions, setPositions] = React.useState({});

  React.useEffect(() => {
    if (!nodes.length) return;

    // Force-directed layout simulation
    const width = 800;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;

    // Initialize positions in a circle
    const newPositions = {};
    nodes.forEach((node, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.35;
      newPositions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle)
      };
    });

    // Simple force simulation (10 iterations)
    for (let iter = 0; iter < 10; iter++) {
      // Repulsion between nodes
      nodes.forEach((n1, i) => {
        nodes.forEach((n2, j) => {
          if (i >= j) return;
          const dx = newPositions[n2.id].x - newPositions[n1.id].x;
          const dy = newPositions[n2.id].y - newPositions[n1.id].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = 500 / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          newPositions[n1.id].x -= fx;
          newPositions[n1.id].y -= fy;
          newPositions[n2.id].x += fx;
          newPositions[n2.id].y += fy;
        });
      });

      // Attraction along edges
      edges.forEach(edge => {
        const source = newPositions[edge.source];
        const target = newPositions[edge.target];
        if (!source || !target) return;
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = dist * 0.01;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        source.x += fx;
        source.y += fy;
        target.x -= fx;
        target.y -= fy;
      });

      // Center gravity
      nodes.forEach(node => {
        const dx = centerX - newPositions[node.id].x;
        const dy = centerY - newPositions[node.id].y;
        newPositions[node.id].x += dx * 0.01;
        newPositions[node.id].y += dy * 0.01;
      });
    }

    setPositions(newPositions);
  }, [nodes, edges]);

  if (!nodes.length) {
    return <div className="graph-empty">No network data available</div>;
  }

  return (
    <div className="network-graph">
      <svg width="100%" height="100%" viewBox="0 0 800 600">
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
          </marker>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        
        {/* Edges */}
        {edges.map((edge, idx) => {
          const source = positions[edge.source];
          const target = positions[edge.target];
          if (!source || !target) return null;
          
          return (
            <line
              key={idx}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="#444"
              strokeWidth={Math.min(edge.weight / 3, 4)}
              opacity={0.4}
              markerEnd="url(#arrowhead)"
            />
          );
        })}
        
        {/* Nodes */}
        {nodes.map((node) => {
          const pos = positions[node.id];
          if (!pos) return null;
          const size = 8 + (node.degree_centrality || 0) * 25;
          
          return (
            <g key={node.id}>
              <circle
                cx={pos.x}
                cy={pos.y}
                r={size}
                fill={node.suspicious ? '#ff4444' : '#4CAF50'}
                opacity={0.9}
                stroke={node.suspicious ? '#ff0000' : '#2E7D32'}
                strokeWidth={3}
                filter={node.suspicious ? 'url(#glow)' : 'none'}
              />
              <text
                x={pos.x}
                y={pos.y + 4}
                fontSize="11"
                fill="#fff"
                textAnchor="middle"
                fontWeight="bold"
              >
                {node.id.split('.').slice(-2).join('.')}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
