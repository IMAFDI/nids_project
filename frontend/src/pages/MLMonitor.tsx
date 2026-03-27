import { useEffect, useState } from 'react';
import { Brain, TrendingUp, Activity } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';

export default function MLMonitor() {
  const [modelVersion, setModelVersion] = useState('v2024.03.27');
  const [lastRetrain, setLastRetrain] = useState('2024-03-27 10:30:00');

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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">ML Model Monitor</h1>
        <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          Trigger Retraining
        </button>
      </div>

      {/* Model Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-2">
            <Brain className="w-6 h-6 text-blue-600" />
            <h3 className="font-semibold text-gray-900">Model Version</h3>
          </div>
          <p className="text-2xl font-bold text-gray-900">{modelVersion}</p>
          <p className="text-sm text-gray-600 mt-1">Active ensemble model</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-2">
            <TrendingUp className="w-6 h-6 text-green-600" />
            <h3 className="font-semibold text-gray-900">Ensemble F1 Score</h3>
          </div>
          <p className="text-2xl font-bold text-gray-900">0.91</p>
          <p className="text-sm text-gray-600 mt-1">Voting threshold: 2/3</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-2">
            <Activity className="w-6 h-6 text-purple-600" />
            <h3 className="font-semibold text-gray-900">Last Retrain</h3>
          </div>
          <p className="text-2xl font-bold text-gray-900">{lastRetrain}</p>
          <p className="text-sm text-gray-600 mt-1">Next: 24h window</p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Feature Importance */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Feature Importance</h2>
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
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Anomaly Score Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={anomalyDistribution}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="range" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#8b5cf6" />
            </BarChart>
          </ResponsiveContainer>
          <p className="text-sm text-gray-600 mt-2">
            Anomaly threshold: 0.6 (lower scores = normal traffic)
          </p>
        </div>
      </div>

      {/* Model Accuracy Table */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Model Performance Metrics</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Model
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Precision
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Recall
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  F1 Score
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {ensembleAccuracy.map((model) => (
                <tr key={model.model} className={model.model === 'Ensemble' ? 'bg-blue-50 font-semibold' : ''}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {model.model}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {(model.precision * 100).toFixed(1)}%
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {(model.recall * 100).toFixed(1)}%
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {(model.f1 * 100).toFixed(1)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Model Details */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Model Configuration</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-medium text-gray-700">Ensemble Strategy:</span>
            <span className="text-gray-900 ml-2">Voting (2 of 3 models)</span>
          </div>
          <div>
            <span className="font-medium text-gray-700">Training Dataset:</span>
            <span className="text-gray-900 ml-2">CICIDS2017 + NSL-KDD</span>
          </div>
          <div>
            <span className="font-medium text-gray-700">Feature Count:</span>
            <span className="text-gray-900 ml-2">15 features</span>
          </div>
          <div>
            <span className="font-medium text-gray-700">Contamination:</span>
            <span className="text-gray-900 ml-2">5%</span>
          </div>
          <div>
            <span className="font-medium text-gray-700">Retrain Interval:</span>
            <span className="text-gray-900 ml-2">24 hours</span>
          </div>
          <div>
            <span className="font-medium text-gray-700">Training Window:</span>
            <span className="text-gray-900 ml-2">Last 168 hours</span>
          </div>
        </div>
      </div>
    </div>
  );
}
