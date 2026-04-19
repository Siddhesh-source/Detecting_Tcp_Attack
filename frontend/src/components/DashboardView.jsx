import React from 'react';
import GlobalStatus from './GlobalStatus';
import AlertSummary from './AlertSummary';
import AnalyticsSection from './AnalyticsSection';
import StoryBanner from './StoryBanner';
import Controls from './Controls';
import './DashboardView.css';

export default function DashboardView({
  flows, alerts, stats, metrics, featureImportance, layerStats,
  connected, capturing, captureIface, threshold, setThreshold, lastUpdate,
  stories, scoreHistory, flowAnalytics, threatLevel,
  onRefresh, onRefreshMetrics, onStartCapture, onStopCapture
}) {
  return (
    <div className="dashboard-view">
      <GlobalStatus
        connected={connected}
        threatLevel={threatLevel}
        alertCount={alerts.length}
        capturing={capturing}
        captureIface={captureIface}
        lastUpdate={lastUpdate}
      />

      <StoryBanner stories={stories} />

      <section className="view-section">
        <AlertSummary
          alerts={alerts}
          stats={stats}
          metrics={metrics}
          featureImportance={featureImportance}
          layerStats={layerStats}
        />
      </section>

      <Controls
        threshold={threshold}
        onThresholdChange={setThreshold}
        onRefresh={onRefresh}
        onRefreshMetrics={onRefreshMetrics}
        onStartCapture={onStartCapture}
        onStopCapture={onStopCapture}
        capturing={capturing}
        flaggingPct={flows.length ? ((alerts.length / flows.length) * 100).toFixed(1) : '0.0'}
      />

      <section className="view-section">
        <AnalyticsSection
          flows={flows}
          layerStats={layerStats}
          flowAnalytics={flowAnalytics}
          featureImportance={featureImportance}
          scoreHistory={scoreHistory}
          threshold={threshold}
          metrics={metrics}
        />
      </section>
    </div>
  );
}
