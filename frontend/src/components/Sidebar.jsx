import React from 'react';
import { FiHome, FiActivity, FiShield, FiCpu, FiLayers, FiDatabase, FiAlertTriangle, FiSettings } from 'react-icons/fi';
import './Sidebar.css';

export default function Sidebar({ activeView, onViewChange, alertCount, connected }) {
  const navSections = [
    {
      title: 'OVERVIEW',
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: FiHome },
        { id: 'alerts', label: 'Alerts', icon: FiAlertTriangle, badge: alertCount }
      ]
    },
    {
      title: 'ANALYSIS',
      items: [
        { id: 'topology', label: 'Network Topology', icon: FiActivity },
        { id: 'explainability', label: 'SHAP Explainability', icon: FiCpu },
        { id: 'baseline', label: 'Behavioral Baseline', icon: FiLayers },
        { id: 'threat-intel', label: 'Threat Intelligence', icon: FiShield }
      ]
    },
    {
      title: 'DATA',
      items: [
        { id: 'flows', label: 'Flow Table', icon: FiDatabase }
      ]
    }
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <FiShield size={24} />
          <span>Covert Detector</span>
        </div>
      </div>

      <div className="sidebar-nav">
        {navSections.map(section => (
          <div key={section.title} className="nav-section">
            <div className="nav-section-title">{section.title}</div>
            {section.items.map(item => (
              <div
                key={item.id}
                className={`nav-item ${activeView === item.id ? 'active' : ''}`}
                onClick={() => onViewChange(item.id)}
              >
                <item.icon className="nav-item-icon" />
                <span>{item.label}</span>
                {item.badge > 0 && <span className="nav-item-badge">{item.badge}</span>}
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="sidebar-footer">
        <div className="connection-status">
          <div className={`status-dot ${connected ? '' : 'disconnected'}`} />
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
      </div>
    </div>
  );
}
