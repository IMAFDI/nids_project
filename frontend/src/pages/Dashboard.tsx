import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, TrendingUp, Server, Shield, Wifi, WifiOff } from 'lucide-react';
import { fetchStats, fetchSystemMetrics } from '../lib/api';
import { nidsWebSocket } from '../lib/websocket';
import { Stats, SystemMetrics } from '../types';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import LiveEventFeed from '../components/LiveEventFeed';
import LiveMetrics from '../components/LiveMetrics';
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
  const [connected, setConnected] = useState(false);
  const [recentEvents, setRecentEvents] = useState<number>(0);

  useEffect(() => {
    // Connect WebSocket
    nidsWebSocket.connect();
    
    const unsubConnection = nidsWebSocket.onConnectionChange(setConnected);
    const unsubEvents = nidsWebSocket.onEvent(() => {
      setRecentEvents(prev => prev + 1);
    });
    
    return () => {
      unsubConnection();
      unsubEvents();
    };
  }, []);

  useEffect(() => {
    const loadData = async () => {
      try {
        const [statsData, metricsData] = await Promise.all([
          fetchStats(),
          fetchSystemMetrics(),
        ]);
        
        // Transform API response to match Stats interface
        const transformedStats = {
          total_events: statsData.total || 0,
          events_by_severity: {
            LOW: statsData.low || 0,
            MEDIUM: statsData.medium || 0,
            HIGH: statsData.high || 0,
            CRITICAL: statsData.critical || 0,
          },
          events_last_24h: statsData.recent_24h || 0,
          events_last_7d: 0,
          events_last_30d: 0,
          top_attackers: statsData.top_sources || [],
        };
        
        setStats(transformedStats);
        setMetrics(metricsData);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 5000); // Faster refresh
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-pulse text-slate-400">Initializing NIDS Dashboard...</div>
      </div>
    );
  }

  const severityData = stats?.events_by_severity
    ? Object.entries(stats.events_by_severity).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="nids-page">
      {/* Header with Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h1 className="nids-title">NIDS Dashboard</h1>
          <div className={clsx(
            'flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium border',
            connected ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/10 text-rose-300 border-rose-500/40'
          )}>
            {connected ? <Wifi className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />}
            {connected ? 'Live' : 'Connecting...'}
          </div>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <Shield className="w-4 h-4" />
          Detection Engine Active
        </div>
      </div>

      {/* Real-time Metrics Bar */}
      <LiveMetrics />

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Events"
          value={stats?.total_events || 0}
          icon={Activity}
          color="blue"
          live={recentEvents > 0}
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
          pulse={stats?.events_by_severity?.CRITICAL ? stats.events_by_severity.CRITICAL > 0 : false}
        />
        <StatCard
          title="High Events"
          value={stats?.events_by_severity?.HIGH || 0}
          icon={Server}
          color="orange"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Event Feed - Takes 2 columns */}
        <div className="lg:col-span-2">
          <LiveEventFeed maxEvents={100} />
        </div>

        {/* Right Sidebar */}
        <div className="space-y-6">
          {/* Severity Breakdown */}
          <div className="nids-card p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-4">Severity Distribution</h2>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-48 flex items-center justify-center text-slate-500">
                No events yet
              </div>
            )}
          </div>

          {/* Top Attackers */}
          <div className="nids-card p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-4">Top Threat Sources</h2>
            <div className="space-y-3">
              {stats?.top_attackers?.slice(0, 5).map((attacker, idx) => (
                <div key={idx} className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 flex items-center justify-center bg-rose-500/15 text-rose-300 text-xs font-bold rounded">
                      {idx + 1}
                    </span>
                    <span className="text-sm font-mono text-slate-200">{attacker.src_ip}</span>
                  </div>
                  <span className="text-sm font-medium text-slate-400">{attacker.count} events</span>
                </div>
              ))}
              {(!stats?.top_attackers || stats.top_attackers.length === 0) && (
                <div className="text-center text-slate-500 py-4">No attackers detected</div>
              )}
            </div>
          </div>

          {/* System Status */}
          <div className="nids-card p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-4">System Status</h2>
            <div className="space-y-3">
              <StatusItem label="Detection Engine" status="running" />
              <StatusItem label="Traffic Simulator" status="running" />
              <StatusItem label="WebSocket" status={connected ? 'connected' : 'disconnected'} />
              <div className="pt-2 border-t border-slate-800">
                <div className="text-xs text-gray-500">
                  Uptime: {formatUptime(metrics?.uptime_seconds || 0)}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color, pulse = false, live = false }: {
  title: string;
  value: number;
  icon: typeof Activity;
  color: string;
  pulse?: boolean;
  live?: boolean;
}) {
  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    red: 'bg-red-500',
    purple: 'bg-purple-500',
    orange: 'bg-orange-500',
  };

  return (
    <div className={clsx(
      'nids-kpi relative overflow-hidden',
      pulse && 'ring-2 ring-rose-500 animate-pulse'
    )}>
      {live && (
        <div className="absolute top-2 right-2">
          <span className="flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
          </span>
        </div>
      )}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-slate-400">{title}</p>
          <p className="text-2xl font-bold text-slate-100 mt-2">{value.toLocaleString()}</p>
        </div>
        <div className={clsx('p-3 rounded-full', colorClasses[color as keyof typeof colorClasses])}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  );
}

function StatusItem({ label, status }: { label: string; status: 'running' | 'stopped' | 'connected' | 'disconnected' }) {
  const statusConfig = {
    running: { color: 'bg-emerald-400', text: 'Running' },
    stopped: { color: 'bg-rose-500', text: 'Stopped' },
    connected: { color: 'bg-emerald-400', text: 'Connected' },
    disconnected: { color: 'bg-amber-400', text: 'Connecting...' },
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-slate-300">{label}</span>
      <div className="flex items-center gap-2">
        <span className={clsx('w-2 h-2 rounded-full', config.color)} />
        <span className="text-xs text-slate-400">{config.text}</span>
      </div>
    </div>
  );
}

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}
