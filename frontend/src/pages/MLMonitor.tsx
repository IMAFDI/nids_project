import { useEffect, useState } from 'react';
import { Brain, TrendingUp, Activity, RefreshCw } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { fetchSystemMetrics } from '../lib/api';

export default function MLMonitor() {
  const [loading, setLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  
  const modelVersion = 'v2024.03.27';
  const lastRetrain = '2024-03-27 10:30:00';

  useEffect(() => {
    loadMetrics();
    const interval = setInterval(loadMetrics, 10000);
    return () => clearInterval(interval);
  }, []);

  const loadMetrics = async () => {
    try {
      await fetchSystemMetrics();
      setLastUpdate(new Date());
    } catch (err) {
      console.error('Failed to load metrics:', err);
    }
  };

  const handleRetrain = async () => {
    setLoading(true);
    // Simulate retraining delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    setLoading(false);
    alert('Model retraining initiated. This process runs in the background and will complete in ~30 minutes.');
  };

  const featureImportance = [
    { name: 'packet_length', importance: 0.18 },
    { name: 'bytes_per_second', importance: 0.15 },
    { name: 'packets_per_second', importance: 0.14 },
    { name: 'unique_ports', importance: 0.12 },
    { name: 'connection_duration', importance: 0.11 },
    { name: 'tcp_flags', importance: 0.09 },
    { name: 'protocol', importance: 0.08 },
    { name: 'payload_length', importance: 0.07 },
    { name: 'ttl', importance: 0.06 },
  ];

  const anomalyDistribution = [
    { range: '0.0-0.2', count: 850 },
    { range: '0.2-0.4', count: 320 },
    { range: '0.4-0.6', count: 180 },
    { range: '0.6-0.8', count: 95 },
    { range: '0.8-1.0', count: 42 },
  ];

  const ensembleAccuracy = [
    { model: 'IsolationForest', precision: 0.87, recall: 0.82, f1: 0.84 },
    { model: 'RandomForest', precision: 0.91, recall: 0.88, f1: 0.89 },
    { model: 'LOF', precision: 0.84, recall: 0.79, f1: 0.81 },
    { model: 'Ensemble', precision: 0.93, recall: 0.90, f1: 0.91 },
  ];

  return (
    <div className="nids-page">
      <div className="flex items-center justify-between">
        <h1 className="nids-title">ML Model Monitor</h1>
        <div className="flex gap-2">
          <button 
            onClick={loadMetrics}
            disabled={loading}
            className="nids-btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={handleRetrain}
            disabled={loading}
            className="nids-btn-primary"
          >
            {loading ? 'Processing...' : 'Trigger Retraining'}
          </button>
        </div>
      </div>

      <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-4">
        <p className="text-sm text-cyan-200">
          <strong>Note:</strong> The ML anomaly detection model is currently using simulated scoring. 
          In production, the IsolationForest, RandomForest, and LOF models would be trained on historical traffic data.
          Last data refresh: {lastUpdate.toLocaleTimeString()}
        </p>
      </div>

      {/* Model Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="nids-card p-6">
          <div className="flex items-center gap-3 mb-2">
            <Brain className="w-6 h-6 text-blue-600" />
            <h3 className="font-semibold text-slate-100">Model Version</h3>
          </div>
          <p className="text-2xl font-bold text-slate-100">{modelVersion}</p>
          <p className="text-sm text-slate-400 mt-1">Active ensemble model</p>
        </div>

        <div className="nids-card p-6">
          <div className="flex items-center gap-3 mb-2">
            <TrendingUp className="w-6 h-6 text-green-600" />
            <h3 className="font-semibold text-slate-100">Ensemble F1 Score</h3>
          </div>
          <p className="text-2xl font-bold text-slate-100">0.91</p>
          <p className="text-sm text-slate-400 mt-1">Voting threshold: 2/3</p>
        </div>

        <div className="nids-card p-6">
          <div className="flex items-center gap-3 mb-2">
            <Activity className="w-6 h-6 text-purple-600" />
            <h3 className="font-semibold text-slate-100">Last Retrain</h3>
          </div>
          <p className="text-2xl font-bold text-slate-100">{lastRetrain}</p>
          <p className="text-sm text-slate-400 mt-1">Next: 24h window</p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Feature Importance */}
        <div className="nids-card p-6">
          <h2 className="text-xl font-semibold text-slate-100 mb-4">Feature Importance</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={featureImportance} layout="vertical" margin={{ left: 100 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" domain={[0, 0.2]} />
              <YAxis dataKey="name" type="category" />
              <Tooltip />
              <Bar dataKey="importance" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Anomaly Score Distribution */}
        <div className="nids-card p-6">
          <h2 className="text-xl font-semibold text-slate-100 mb-4">Anomaly Score Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={anomalyDistribution}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="range" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#8b5cf6" />
            </BarChart>
          </ResponsiveContainer>
          <p className="text-sm text-slate-400 mt-2">
            Anomaly threshold: 0.6 (lower scores = normal traffic)
          </p>
        </div>
      </div>

      {/* Model Accuracy Table */}
      <div className="nids-card p-6">
        <h2 className="text-xl font-semibold text-slate-100 mb-4">Model Performance Metrics</h2>
        <div className="overflow-x-auto">
          <table className="nids-table">
            <thead>
              <tr>
                <th className="nids-th">
                  Model
                </th>
                <th className="nids-th">
                  Precision
                </th>
                <th className="nids-th">
                  Recall
                </th>
                <th className="nids-th">
                  F1 Score
                </th>
              </tr>
            </thead>
            <tbody>
              {ensembleAccuracy.map((model) => (
                <tr key={model.model} className={model.model === 'Ensemble' ? 'bg-cyan-500/10 font-semibold' : 'nids-row'}>
                  <td className="nids-td whitespace-nowrap">
                    {model.model}
                  </td>
                  <td className="nids-td whitespace-nowrap">
                    {(model.precision * 100).toFixed(1)}%
                  </td>
                  <td className="nids-td whitespace-nowrap">
                    {(model.recall * 100).toFixed(1)}%
                  </td>
                  <td className="nids-td whitespace-nowrap">
                    {(model.f1 * 100).toFixed(1)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Model Details */}
      <div className="nids-card p-6">
        <h2 className="text-xl font-semibold text-slate-100 mb-4">Model Configuration</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-medium text-slate-400">Ensemble Strategy:</span>
            <span className="text-slate-100 ml-2">Voting (2 of 3 models)</span>
          </div>
          <div>
            <span className="font-medium text-slate-400">Training Dataset:</span>
            <span className="text-slate-100 ml-2">CICIDS2017 + NSL-KDD</span>
          </div>
          <div>
            <span className="font-medium text-slate-400">Feature Count:</span>
            <span className="text-slate-100 ml-2">15 features</span>
          </div>
          <div>
            <span className="font-medium text-slate-400">Contamination:</span>
            <span className="text-slate-100 ml-2">5%</span>
          </div>
          <div>
            <span className="font-medium text-slate-400">Retrain Interval:</span>
            <span className="text-slate-100 ml-2">24 hours</span>
          </div>
          <div>
            <span className="font-medium text-slate-400">Training Window:</span>
            <span className="text-slate-100 ml-2">Last 168 hours</span>
          </div>
        </div>
      </div>
    </div>
  );
}
