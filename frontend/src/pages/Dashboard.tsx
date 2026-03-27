import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, TrendingUp, Server } from 'lucide-react';
import { fetchStats, fetchSystemMetrics } from '../lib/api';
import { Stats, SystemMetrics } from '../types';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import clsx from 'clsx';

const SEVERITY_COLORS = {
  LOW: '#10b981',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#991b1b',
};

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadData = async () => {
      try {
        const [statsData, metricsData] = await Promise.all([
          fetchStats(),
          fetchSystemMetrics(),
        ]);
        setStats(statsData);
        setMetrics(metricsData);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-gray-500">Loading dashboard...</div>
      </div>
    );
  }

  const severityData = stats?.events_by_severity
    ? Object.entries(stats.events_by_severity).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Dashboard Overview</h1>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Events"
          value={stats?.total_events || 0}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Last 24h"
          value={stats?.events_last_24h || 0}
          icon={TrendingUp}
          color="green"
        />
        <StatCard
          title="Critical Events"
          value={stats?.events_by_severity?.CRITICAL || 0}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="Queue Depth"
          value={metrics?.queue_depth || 0}
          icon={Server}
          color="purple"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Severity Breakdown</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* System Metrics */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">System Health</h2>
          <div className="space-y-4">
            <MetricBar label="CPU Usage" value={metrics?.cpu_percent || 0} max={100} unit="%" />
            <MetricBar label="Memory Usage" value={metrics?.memory_percent || 0} max={100} unit="%" />
            <MetricBar label="Packets/sec" value={metrics?.packets_per_second || 0} max={1000} unit=" pps" />
          </div>
          <div className="mt-4 text-sm text-gray-600">
            Uptime: {formatUptime(metrics?.uptime_seconds || 0)}
          </div>
        </div>
      </div>

      {/* Top Attackers */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Top 5 Attacker IPs</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Source IP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Event Count
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {stats?.top_attackers?.slice(0, 5).map((attacker, idx) => (
                <tr key={idx}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {attacker.src_ip}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {attacker.count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color }: any) {
  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    red: 'bg-red-500',
    purple: 'bg-purple-500',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-2">{value.toLocaleString()}</p>
        </div>
        <div className={clsx('p-3 rounded-full', colorClasses[color as keyof typeof colorClasses])}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  );
}

function MetricBar({ label, value, max, unit }: any) {
  const percentage = Math.min((value / max) * 100, 100);
  const color = percentage > 80 ? 'bg-red-500' : percentage > 60 ? 'bg-yellow-500' : 'bg-green-500';

  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-700">{label}</span>
        <span className="text-gray-900 font-medium">{value.toFixed(1)}{unit}</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div className={clsx('h-2 rounded-full transition-all', color)} style={{ width: `${percentage}%` }} />
      </div>
    </div>
  );
}

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}
