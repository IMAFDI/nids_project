import { useEffect, useState } from 'react';
import { CheckCircle, Download, ChevronDown, ChevronUp } from 'lucide-react';
import { fetchEvents, acknowledgeEvent, exportEvents } from '../lib/api';
import { Event } from '../types';
import { format } from 'date-fns';
import clsx from 'clsx';

const SEVERITY_COLORS = {
  LOW: 'bg-green-100 text-green-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  HIGH: 'bg-orange-100 text-orange-800',
  CRITICAL: 'bg-red-100 text-red-800',
};

export default function Events() {
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [filters, setFilters] = useState({ severity: '', src_ip: '' });

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 5000); // Auto-refresh
    return () => clearInterval(interval);
  }, [filters]);

  const loadEvents = async () => {
    try {
      const data = await fetchEvents(1, 100, filters);
      setEvents(data.events || []);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  };

  // Calculate statistics
  const stats = {
    total: events.length,
    acknowledged: events.filter(e => e.acknowledged).length,
    critical: events.filter(e => e.severity === 'CRITICAL').length,
    high: events.filter(e => e.severity === 'HIGH').length,
    medium: events.filter(e => e.severity === 'MEDIUM').length,
    low: events.filter(e => e.severity === 'LOW').length,
  };

  const handleAcknowledge = async (eventId: number) => {
    try {
      await acknowledgeEvent(eventId);
      setEvents(events.map(e => e.id === eventId ? { ...e, acknowledged: true } : e));
    } catch (err) {
      console.error('Failed to acknowledge event:', err);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const blob = await exportEvents(format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `events.${format}`;
      a.click();
    } catch (err) {
      console.error('Failed to export events:', err);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-96">Loading events...</div>;
  }

  return (
    <div className="nids-page">
      <div className="flex items-center justify-between">
        <h1 className="nids-title">Security Events</h1>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport('csv')}
            className="nids-btn-secondary"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            className="nids-btn-primary"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Summary Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <div className="nids-kpi">
          <div className="text-2xl font-bold text-slate-100">{stats.total}</div>
          <div className="text-sm text-slate-400">Total Events</div>
        </div>
        <div className="nids-kpi border border-rose-500/30">
          <div className="text-2xl font-bold text-rose-300">{stats.critical}</div>
          <div className="text-sm text-rose-300">Critical</div>
        </div>
        <div className="nids-kpi border border-orange-500/30">
          <div className="text-2xl font-bold text-orange-300">{stats.high}</div>
          <div className="text-sm text-orange-300">High</div>
        </div>
        <div className="nids-kpi border border-amber-500/30">
          <div className="text-2xl font-bold text-amber-300">{stats.medium}</div>
          <div className="text-sm text-amber-300">Medium</div>
        </div>
        <div className="nids-kpi border border-emerald-500/30">
          <div className="text-2xl font-bold text-emerald-300">{stats.low}</div>
          <div className="text-sm text-emerald-300">Low</div>
        </div>
        <div className="nids-kpi border border-cyan-500/30">
          <div className="text-2xl font-bold text-cyan-300">{stats.acknowledged}</div>
          <div className="text-sm text-cyan-300">Acknowledged</div>
        </div>
      </div>

      {/* Filters */}
      <div className="nids-card p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="nids-label">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="nids-input"
            >
              <option value="">All</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
          <div>
            <label className="nids-label">Source IP</label>
            <input
              type="text"
              value={filters.src_ip}
              onChange={(e) => setFilters({ ...filters, src_ip: e.target.value })}
              placeholder="Filter by IP..."
              className="nids-input"
            />
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="nids-table-wrap">
        <table className="nids-table">
          <thead>
            <tr>
              <th className="nids-th">
                Time
              </th>
              <th className="nids-th">
                Severity
              </th>
              <th className="nids-th">
                Source
              </th>
              <th className="nids-th">
                Destination
              </th>
              <th className="nids-th">
                Rule
              </th>
              <th className="nids-th">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <>
                <tr key={event.id} className="nids-row">
                  <td className="nids-td whitespace-nowrap">
                    {format(new Date(event.timestamp), 'MMM dd, HH:mm:ss')}
                  </td>
                  <td className="nids-td whitespace-nowrap">
                    <span className={clsx('px-2 py-1 text-xs font-semibold rounded-full', SEVERITY_COLORS[event.severity])}>
                      {event.severity}
                    </span>
                  </td>
                  <td className="nids-td whitespace-nowrap">
                    {event.src_ip}:{event.src_port}
                  </td>
                  <td className="nids-td whitespace-nowrap">
                    {event.dst_ip}:{event.dst_port}
                  </td>
                  <td className="nids-td whitespace-nowrap text-slate-400">
                    {event.rule_triggered || '-'}
                  </td>
                  <td className="nids-td whitespace-nowrap text-sm font-medium">
                    <div className="flex items-center gap-2">
                      {!event.acknowledged && (
                        <button
                          onClick={() => handleAcknowledge(event.id)}
                          className="text-cyan-300 hover:text-cyan-200"
                        >
                          <CheckCircle className="w-5 h-5" />
                        </button>
                      )}
                        <button
                          onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
                          className="text-slate-400 hover:text-slate-200"
                        >
                        {expandedId === event.id ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                      </button>
                    </div>
                  </td>
                </tr>
                {expandedId === event.id && (
                  <tr>
                    <td colSpan={6} className="px-6 py-4 bg-slate-900/40">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="font-medium text-slate-400">Protocol:</span> {event.protocol}
                        </div>
                        <div>
                          <span className="font-medium text-slate-400">Country:</span> {event.country_code || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium text-slate-400">ML Score:</span> {event.ml_score?.toFixed(3) || 'N/A'}
                        </div>
                        <div>
                          <span className="font-medium text-slate-400">Threat Intel:</span> {event.threat_intel_score || 'N/A'}
                        </div>
                        {event.description && (
                          <div className="col-span-2">
                            <span className="font-medium text-slate-400">Description:</span> {event.description}
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
