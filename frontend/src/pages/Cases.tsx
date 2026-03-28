import { useEffect, useState } from 'react';
import { format } from 'date-fns';
import clsx from 'clsx';
import {
  fetchCases,
  createCase,
  fetchCaseDetail,
  addCaseNote,
  linkCaseEvent,
  unlinkCaseEvent,
  fetchEvents,
} from '../lib/api';
import { CaseItem, CaseDetail, Event } from '../types';
import { Plus, Link2, Unlink2 } from 'lucide-react';

const LEVEL_COLORS: Record<string, string> = {
  LOW: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
  HIGH: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  CRITICAL: 'bg-rose-500/15 text-rose-300 border border-rose-500/30',
};

const STATUS_COLORS: Record<string, string> = {
  OPEN: 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30',
  IN_PROGRESS: 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30',
  ON_HOLD: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
  CLOSED: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
};

export default function Cases() {
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [availableEvents, setAvailableEvents] = useState<Event[]>([]);
  const [newNote, setNewNote] = useState('');
  const [eventToLink, setEventToLink] = useState('');
  const [filters, setFilters] = useState({ status: '', severity: '', owner_user_id: '' });
  const [form, setForm] = useState({
    title: '',
    severity: 'MEDIUM',
    priority: 'MEDIUM',
    owner_user_id: '',
    event_ids: '',
  });

  useEffect(() => {
    loadCases();
  }, [filters.status, filters.severity, filters.owner_user_id]);

  useEffect(() => {
    fetchEvents(1, 100)
      .then((data) => setAvailableEvents(data.events || []))
      .catch(() => setAvailableEvents([]));
  }, []);

  const loadCases = async () => {
    setLoading(true);
    try {
      const data = await fetchCases(1, 100, {
        status: filters.status || undefined,
        severity: filters.severity || undefined,
        owner_user_id: filters.owner_user_id ? Number(filters.owner_user_id) : undefined,
      });
      setCases(data.cases || []);
      if (!selectedCaseId && data.cases?.length) {
        setSelectedCaseId(data.cases[0].id);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedCaseId) {
      loadDetail(selectedCaseId);
    }
  }, [selectedCaseId]);

  const loadDetail = async (id: number) => {
    setDetailLoading(true);
    try {
      const data = await fetchCaseDetail(id);
      setDetail(data);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!form.title.trim()) return;
    const eventIds = form.event_ids
      .split(',')
      .map((v) => Number(v.trim()))
      .filter((v) => Number.isFinite(v) && v > 0);
    await createCase({
      title: form.title.trim(),
      severity: form.severity,
      priority: form.priority,
      owner_user_id: form.owner_user_id ? Number(form.owner_user_id) : undefined,
      event_ids: eventIds,
    });
    setShowCreate(false);
    setForm({ title: '', severity: 'MEDIUM', priority: 'MEDIUM', owner_user_id: '', event_ids: '' });
    await loadCases();
  };

  const submitNote = async () => {
    if (!selectedCaseId || !newNote.trim()) return;
    await addCaseNote(selectedCaseId, newNote.trim());
    setNewNote('');
    await loadDetail(selectedCaseId);
  };

  const attachEvent = async () => {
    if (!selectedCaseId || !eventToLink) return;
    await linkCaseEvent(selectedCaseId, Number(eventToLink));
    setEventToLink('');
    await loadDetail(selectedCaseId);
  };

  const detachEvent = async (eventId: number) => {
    if (!selectedCaseId) return;
    await unlinkCaseEvent(selectedCaseId, eventId);
    await loadDetail(selectedCaseId);
  };

  return (
    <div className="nids-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="nids-title">Cases</h1>
          <p className="nids-subtitle">Track investigations and evidence around intrusion events.</p>
        </div>
        <button className="nids-btn-primary" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4" />
          New Case
        </button>
      </div>

      <div className="nids-card p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="nids-label">Status</label>
            <select className="nids-input" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
              <option value="">All</option>
              <option value="OPEN">Open</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="ON_HOLD">On Hold</option>
              <option value="CLOSED">Closed</option>
            </select>
          </div>
          <div>
            <label className="nids-label">Severity</label>
            <select className="nids-input" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
              <option value="">All</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
          <div>
            <label className="nids-label">Owner User ID</label>
            <input
              className="nids-input"
              placeholder="e.g. 1"
              value={filters.owner_user_id}
              onChange={(e) => setFilters({ ...filters, owner_user_id: e.target.value })}
            />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="nids-table-wrap">
          <table className="nids-table">
            <thead>
              <tr>
                <th className="nids-th">ID</th>
                <th className="nids-th">Title</th>
                <th className="nids-th">Status</th>
                <th className="nids-th">Severity</th>
                <th className="nids-th">Priority</th>
                <th className="nids-th">Updated</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td className="nids-td" colSpan={6}>Loading cases...</td></tr>
              ) : cases.length === 0 ? (
                <tr><td className="nids-td" colSpan={6}>No cases found.</td></tr>
              ) : (
                cases.map((c) => (
                  <tr
                    key={c.id}
                    className={clsx('nids-row cursor-pointer', selectedCaseId === c.id && 'bg-slate-800/50')}
                    onClick={() => setSelectedCaseId(c.id)}
                  >
                    <td className="nids-td">#{c.id}</td>
                    <td className="nids-td">{c.title}</td>
                    <td className="nids-td"><span className={clsx('px-2 py-1 rounded-full text-xs font-semibold', STATUS_COLORS[c.status] || STATUS_COLORS.OPEN)}>{c.status}</span></td>
                    <td className="nids-td"><span className={clsx('px-2 py-1 rounded-full text-xs font-semibold', LEVEL_COLORS[c.severity] || LEVEL_COLORS.MEDIUM)}>{c.severity}</span></td>
                    <td className="nids-td">{c.priority}</td>
                    <td className="nids-td">{format(new Date(c.updated_at), 'MMM dd, HH:mm')}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="nids-card p-4 space-y-4">
          {!selectedCaseId ? (
            <div className="text-slate-400">Select a case to inspect details.</div>
          ) : detailLoading ? (
            <div className="text-slate-400">Loading case details...</div>
          ) : !detail ? (
            <div className="text-slate-400">Case not found.</div>
          ) : (
            <>
              <div>
                <h2 className="text-lg font-semibold text-slate-100">{detail.title}</h2>
                <p className="text-sm text-slate-400">Case #{detail.id} • Owner {detail.owner_user_id ?? 'Unassigned'}</p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-300">Linked Events</h3>
                  <div className="flex items-center gap-2">
                    <select className="nids-input !py-2 !text-xs" value={eventToLink} onChange={(e) => setEventToLink(e.target.value)}>
                      <option value="">Select event</option>
                      {availableEvents.map((e) => (
                        <option key={e.id} value={e.id}>
                          #{e.id} {e.severity} {e.src_ip}
                        </option>
                      ))}
                    </select>
                    <button className="nids-btn-secondary !py-2 !px-3" onClick={attachEvent}><Link2 className="w-4 h-4" /></button>
                  </div>
                </div>
                <div className="space-y-2 max-h-40 overflow-auto">
                  {detail.events.length === 0 ? (
                    <div className="text-sm text-slate-500">No linked events.</div>
                  ) : detail.events.map((e) => (
                    <div key={e.id} className="flex items-center justify-between rounded-lg border border-slate-800 px-3 py-2 text-sm">
                      <div>
                        <span className="text-slate-100">#{e.id}</span>
                        <span className="ml-2 text-slate-400">{e.src_ip} → {e.dst_ip}</span>
                      </div>
                      <button onClick={() => detachEvent(e.id)} className="text-rose-300 hover:text-rose-200">
                        <Unlink2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-sm font-semibold text-slate-300">Notes</h3>
                <div className="space-y-2 max-h-48 overflow-auto">
                  {detail.notes.length === 0 ? (
                    <div className="text-sm text-slate-500">No notes yet.</div>
                  ) : detail.notes.map((n) => (
                    <div key={n.id} className="rounded-lg border border-slate-800 px-3 py-2 text-sm">
                      <div className="text-slate-200">{n.note}</div>
                      <div className="text-xs text-slate-500 mt-1">User {n.author_user_id} • {format(new Date(n.created_at), 'MMM dd, HH:mm')}</div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input
                    className="nids-input"
                    placeholder="Add an investigation note..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                  />
                  <button className="nids-btn-primary" onClick={submitNote}>Add</button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {showCreate && (
        <div className="fixed inset-0 z-40 bg-slate-950/70 flex items-center justify-center p-4">
          <div className="nids-card w-full max-w-xl p-6 space-y-4">
            <h2 className="text-lg font-semibold text-slate-100">Create Case</h2>
            <div>
              <label className="nids-label">Title</label>
              <input className="nids-input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="nids-label">Severity</label>
                <select className="nids-input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
              <div>
                <label className="nids-label">Priority</label>
                <select className="nids-input" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
            </div>
            <div>
              <label className="nids-label">Owner User ID (optional)</label>
              <input className="nids-input" value={form.owner_user_id} onChange={(e) => setForm({ ...form, owner_user_id: e.target.value })} />
            </div>
            <div>
              <label className="nids-label">Initial Event IDs (comma-separated, optional)</label>
              <input className="nids-input" placeholder="e.g. 12,14,88" value={form.event_ids} onChange={(e) => setForm({ ...form, event_ids: e.target.value })} />
            </div>
            <div className="flex justify-end gap-2">
              <button className="nids-btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="nids-btn-primary" onClick={handleCreate}>Create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
