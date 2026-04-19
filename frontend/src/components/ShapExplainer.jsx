import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { FiCpu, FiTrendingUp, FiTrendingDown } from 'react-icons/fi';
import './ShapExplainer.css';

const API = 'http://localhost:8000';

export default function ShapExplainer({ flows }) {
  const [activeTab, setActiveTab] = useState('local');
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [globalImportance, setGlobalImportance] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (activeTab === 'global') {
      fetchGlobalImportance();
    }
  }, [activeTab]);

  const fetchGlobalImportance = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/explain/global`);
      setGlobalImportance(res.data.importance || []);
    } catch (err) {
      console.error('Global importance fetch error:', err);
    }
    setLoading(false);
  };

  const explainFlow = async (flowId) => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/explain/${flowId}`);
      setExplanation(res.data);
      setSelectedFlow(flowId);
    } catch (err) {
      console.error('Flow explanation error:', err);
    }
    setLoading(false);
  };

  const alertFlows = flows.filter(f => f.is_anomaly === 1).slice(0, 20);

  return (
    <div className="shap-explainer">
      <div className="shap-header">
        <h2><FiCpu /> SHAP Explainability</h2>
        <div className="shap-tabs">
          <button
            className={`shap-tab ${activeTab === 'local' ? 'active' : ''}`}
            onClick={() => setActiveTab('local')}
          >
            Local Explanation
          </button>
          <button
            className={`shap-tab ${activeTab === 'global' ? 'active' : ''}`}
            onClick={() => setActiveTab('global')}
          >
            Global Importance
          </button>
        </div>
      </div>

      <div className="shap-content">
        {activeTab === 'local' && (
          <>
            <div className="flow-selector">
              <select
                value={selectedFlow || ''}
                onChange={(e) => explainFlow(e.target.value)}
              >
                <option value="">Select a flow to explain...</option>
                {alertFlows.map(f => (
                  <option key={f.flow_id} value={f.flow_id}>
                    {f.flow_id} (score: {f.suspicion_score?.toFixed(0)})
                  </option>
                ))}
              </select>
            </div>

            {loading && <div className="shap-loading">Calculating SHAP values...</div>}

            {!loading && explanation && (
              <>
                <div className="prediction-summary">
                  <h3>Prediction Summary</h3>
                  <div className="prediction-grid">
                    <div className="prediction-metric">
                      <div className="label">Prediction</div>
                      <div className={`value ${explanation.prediction === 1 ? 'attack' : 'benign'}`}>
                        {explanation.prediction === 1 ? 'ATTACK' : 'BENIGN'}
                      </div>
                    </div>
                    <div className="prediction-metric">
                      <div className="label">Probability</div>
                      <div className="value">{(explanation.probability * 100).toFixed(1)}%</div>
                    </div>
                    <div className="prediction-metric">
                      <div className="label">Base Value</div>
                      <div className="value">{explanation.base_value?.toFixed(3)}</div>
                    </div>
                  </div>
                </div>

                <div className="shap-waterfall">
                  {explanation.top_contributors?.map((contrib, idx) => {
                    const isPositive = contrib.shap_value > 0;
                    const maxAbsValue = Math.max(...explanation.top_contributors.map(c => Math.abs(c.shap_value)));
                    const barWidth = (Math.abs(contrib.shap_value) / maxAbsValue) * 100;

                    return (
                      <motion.div
                        key={contrib.feature}
                        className={`waterfall-item ${isPositive ? 'positive' : 'negative'}`}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.05 }}
                      >
                        <div className="feature-name">{contrib.feature}</div>
                        <div className="feature-value">= {contrib.value?.toFixed(4)}</div>
                        <div className="shap-bar-container">
                          <div className="shap-bar">
                            <div
                              className={`shap-bar-fill ${isPositive ? 'positive' : 'negative'}`}
                              style={{ width: `${barWidth}%` }}
                            >
                              {isPositive ? <FiTrendingUp /> : <FiTrendingDown />}
                            </div>
                          </div>
                          <div className={`shap-value ${isPositive ? 'positive' : 'negative'}`}>
                            {contrib.shap_value > 0 ? '+' : ''}{contrib.shap_value.toFixed(3)}
                          </div>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </>
            )}

            {!loading && !explanation && (
              <div className="shap-empty">
                <FiCpu size={48} />
                <p>Select a flow to see SHAP explanation</p>
              </div>
            )}
          </>
        )}

        {activeTab === 'global' && (
          <>
            {loading && <div className="shap-loading">Loading global importance...</div>}

            {!loading && globalImportance.length > 0 && (
              <div className="global-importance">
                {globalImportance.map((item, idx) => {
                  const maxValue = globalImportance[0]?.mean_abs_shap || 1;
                  const barWidth = (item.mean_abs_shap / maxValue) * 100;

                  return (
                    <motion.div
                      key={item.feature}
                      className="importance-item"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.03 }}
                    >
                      <div className="importance-rank">#{item.importance_rank}</div>
                      <div className="importance-feature">{item.feature}</div>
                      <div className="importance-bar">
                        <div className="importance-bar-fill" style={{ width: `${barWidth}%` }} />
                      </div>
                      <div className="importance-score">{item.mean_abs_shap.toFixed(3)}</div>
                    </motion.div>
                  );
                })}
              </div>
            )}

            {!loading && globalImportance.length === 0 && (
              <div className="shap-empty">
                <FiCpu size={48} />
                <p>No global importance data available</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
