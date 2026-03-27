import { useEffect, useState } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { fetchEvents } from '../lib/api';
import { Event } from '../types';
import clsx from 'clsx';

const geoUrl = 'https://raw.githubusercontent.com/deldersveld/topojson/master/world-countries.json';

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

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadEvents = async () => {
    try {
      const data = await fetchEvents(1, 1000, { severity: selectedSeverity });
      setEvents(data.events || []);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  };

  const countryStats = events.reduce((acc, event) => {
    if (!event.country_code) return acc;
    if (!acc[event.country_code]) {
      acc[event.country_code] = { count: 0, severity: event.severity };
    }
    acc[event.country_code].count++;
    return acc;
  }, {} as Record<string, { count: number; severity: string }>);

  const topCountries = Object.entries(countryStats)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, 10);

  if (loading) {
    return <div className="flex items-center justify-center h-96">Loading threat map...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Global Threat Map</h1>
        
        <div className="flex gap-2">
          <button
            onClick={() => setSelectedSeverity('')}
            className={clsx(
              'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
              selectedSeverity === ''
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
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
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              {severity}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <ComposableMap projectionConfig={{ scale: 147 }}>
          <Geographies geography={geoUrl}>
            {({ geographies }: { geographies: any[] }) =>
              geographies.map((geo: any) => {
                const countryCode = geo.properties.iso_a2 as string;
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
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Top Attack Sources</h2>
          <div className="space-y-2">
            {topCountries.map(([country, stats], idx) => (
              <div key={country} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="text-lg font-bold text-gray-500">#{idx + 1}</span>
                  <span className="font-medium text-gray-900">{country}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-600">{stats.count} events</span>
                  <span
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: SEVERITY_COLORS[stats.severity as keyof typeof SEVERITY_COLORS] }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Legend */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Severity Legend</h2>
          <div className="space-y-3">
            {Object.entries(SEVERITY_COLORS).map(([severity, color]) => (
              <div key={severity} className="flex items-center gap-3">
                <div className="w-8 h-8 rounded" style={{ backgroundColor: color }} />
                <div>
                  <div className="font-medium text-gray-900">{severity}</div>
                  <div className="text-sm text-gray-600">
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
