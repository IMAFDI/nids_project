import { useCallback, useEffect, useState } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { fetchEvents, fetchSystemMetrics } from '../lib/api';
import { nidsWebSocket } from '../lib/websocket';
import { Event } from '../types';
import clsx from 'clsx';
import worldAtlas from 'world-atlas/countries-110m.json';

const geoData = worldAtlas as object;

const SEVERITY_COLORS = {
  LOW: '#10b981',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#991b1b',
};

export default function ThreatMap() {
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [simulatorRunning, setSimulatorRunning] = useState<boolean | null>(null);

  const loadEvents = useCallback(async () => {
    try {
      const data = await fetchEvents(1, 1000, { severity: selectedSeverity });
      setEvents(data.events || []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedSeverity]);

  useEffect(() => {
    setLoading(true);
    loadEvents();
    const interval = setInterval(loadEvents, 30000);
    return () => clearInterval(interval);
  }, [loadEvents]);

  useEffect(() => {
    const loadMetrics = async () => {
      try {
        const metrics = await fetchSystemMetrics();
        setSimulatorRunning(metrics.simulator_status === 'running');
      } catch (err) {
        console.error('Failed to load system metrics:', err);
        setSimulatorRunning(null);
      }
    };
    loadMetrics();
  }, []);

  useEffect(() => {
    nidsWebSocket.connect();
    const unsubscribe = nidsWebSocket.onEvent((message) => {
      const eventData = message?.data;
      if (!eventData?.country_code) return;
      if (selectedSeverity && eventData.severity !== selectedSeverity) return;

      const mapped: Event = {
        id: Number(eventData.id ?? Date.now()),
        timestamp: eventData.timestamp ?? new Date().toISOString(),
        severity: (eventData.severity ?? 'LOW') as Event['severity'],
        src_ip: eventData.src_ip ?? '',
        dst_ip: eventData.dst_ip ?? '',
        src_port: Number(eventData.src_port ?? 0),
        dst_port: Number(eventData.dst_port ?? 0),
        protocol: eventData.protocol ?? '',
        rule_triggered: eventData.rule_name,
        ml_score: eventData.ml_score,
        threat_intel_score: eventData.threat_intel_score,
        country_code: String(eventData.country_code).toUpperCase(),
        acknowledged: false,
        description: eventData.description ?? '',
      };

      setEvents((prev) => {
        const deduped = prev.filter((e) => e.id !== mapped.id);
        return [mapped, ...deduped].slice(0, 1000);
      });
      setLastUpdated(new Date());
    });

    return () => {
      unsubscribe();
    };
  }, [selectedSeverity]);

  const countryStats = events.reduce((acc, event) => {
    const code = event.country_code?.toUpperCase();
    if (!code) return acc;
    if (!acc[code]) {
      acc[code] = { count: 0, severity: event.severity };
    }
    acc[code].count++;
    return acc;
  }, {} as Record<string, { count: number; severity: string }>);

  const topCountries = Object.entries(countryStats)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, 10);

  if (loading) {
    return <div className="flex items-center justify-center h-96 text-slate-400">Loading threat map...</div>;
  }

  return (
    <div className="nids-page">
      <div className="flex items-center justify-between">
        <h1 className="nids-title">Global Threat Map</h1>
        
        <div className="flex gap-2">
          <button
            onClick={() => setSelectedSeverity('')}
            className={clsx(
              'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                selectedSeverity === ''
                  ? 'bg-cyan-500 text-slate-950'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            )}
          >
            All
          </button>
          {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map((severity) => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity(severity)}
              className={clsx(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                selectedSeverity === severity
                  ? 'bg-cyan-500 text-slate-950'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              )}
            >
              {severity}
            </button>
          ))}
        </div>
      </div>

      <div className="nids-card p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm text-slate-300">
          <span className="font-semibold">Data source:</span>{' '}
          {simulatorRunning === true && (
            <span className="text-amber-700">Traffic Simulator (Demo/Synthetic)</span>
          )}
          {simulatorRunning === false && (
            <span className="text-green-700">Live Capture / Ingested Events</span>
          )}
          {simulatorRunning === null && (
            <span className="text-slate-500">Unknown (metrics unavailable)</span>
          )}
        </div>
        <div className="text-sm text-slate-400">
          <span className="font-semibold">Last updated:</span>{' '}
          {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Not yet'}
        </div>
      </div>

      <div className="nids-card p-6">
        <ComposableMap projectionConfig={{ scale: 147 }}>
          <Geographies geography={geoData}>
            {({ geographies }: { geographies: any[] }) =>
              geographies.map((geo: any) => {
                const countryCode = String(
                  geo.properties?.ISO_A2 ?? geo.properties?.iso_a2 ?? ''
                ).toUpperCase();
                const stats = countryStats[countryCode];
                
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={stats ? SEVERITY_COLORS[stats.severity as keyof typeof SEVERITY_COLORS] : '#E5E7EB'}
                    stroke="#fff"
                    strokeWidth={0.5}
                    style={{
                      default: { outline: 'none' },
                      hover: { outline: 'none', fill: '#9CA3AF' },
                      pressed: { outline: 'none' },
                    }}
                  />
                );
              })
            }
          </Geographies>
        </ComposableMap>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Countries */}
        <div className="nids-card p-6">
          <h2 className="text-xl font-semibold text-slate-100 mb-4">Top Attack Sources</h2>
          <div className="space-y-2">
            {topCountries.map(([country, stats], idx) => (
              <div key={country} className="flex items-center justify-between p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                <div className="flex items-center gap-3">
                  <span className="text-lg font-bold text-slate-500">#{idx + 1}</span>
                  <span className="font-medium text-slate-100">{country}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm text-slate-400">{stats.count} events</span>
                  <span
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: SEVERITY_COLORS[stats.severity as keyof typeof SEVERITY_COLORS] }}
                  />
                </div>
              </div>
            ))}
            {topCountries.length === 0 && (
              <div className="text-sm text-slate-500 py-6 text-center">
                No geolocated events yet. Wait for new traffic or clear severity filter.
              </div>
            )}
          </div>
        </div>

        {/* Legend */}
        <div className="nids-card p-6">
          <h2 className="text-xl font-semibold text-slate-100 mb-4">Severity Legend</h2>
          <div className="space-y-3">
            {Object.entries(SEVERITY_COLORS).map(([severity, color]) => (
              <div key={severity} className="flex items-center gap-3">
                <div className="w-8 h-8 rounded" style={{ backgroundColor: color }} />
                <div>
                  <div className="font-medium text-slate-100">{severity}</div>
                  <div className="text-sm text-slate-400">
                    {countryStats && Object.values(countryStats).filter(s => s.severity === severity).length} countries
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
