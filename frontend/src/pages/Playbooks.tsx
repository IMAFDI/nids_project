import { useEffect, useMemo, useState } from 'react';
import { format } from 'date-fns';
import clsx from 'clsx';
import { Play, Plus, Power, Trash2 } from 'lucide-react';
import {
  createPlaybook,
  deletePlaybook,
  fetchPlaybookExecutions,
  fetchPlaybooks,
  testPlaybook,
  togglePlaybook,
  updatePlaybook,
} from '../lib/api';
import { Playbook, PlaybookExecution } from '../types';

const STATUS_COLORS: Record<string, string> = {
  success: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  failed: 'bg-rose-500/15 text-rose-300 border border-rose-500/30',
  skipped: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
};

const ACTION_TEMPLATES = [
  { type: 'notify_channel' },
  { type: 'escalate_event_severity', target_severity: 'HIGH' },
  { type: 'add_to_blocklist' },
  { type: 'create_ticket', provider_type: 'jira' },
];

export default function Playbooks() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<number | null>(null);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [execLoading, setExecLoading] = useState(false);
  const [showEditor, setShowEditor] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState({
    name: '',
    description: '',
    trigger_severities: 'HIGH, CRITICAL',
    trigger_rule_ids: '',
    trigger_event_types: 'signature, anomaly',
    enabled: true,
    actions: JSON.stringify(ACTION_TEMPLATES, null, 2),
  });
  const [testPayload, setTestPayload] = useState('{"severity":"HIGH","event_type":"signature","src_ip":"1.2.3.4","description":"Playbook test"}');
  const [message, setMessage] = useState<string>('');

  const selectedPlaybook = useMemo(
    () => playbooks.find((p) => p.id === selectedPlaybookId) || null,
    [playbooks, selectedPlaybookId]
  );

  useEffect(() => {
    loadPlaybooks();
  }, []);

  useEffect(() => {
    if (selectedPlaybookId) {
      loadExecutions(selectedPlaybookId);
    } else {
      setExecutions([]);
    }
  }, [selectedPlaybookId]);

  const loadPlaybooks = async () => {
    setLoading(true);
    try {
      const rows = await fetchPlaybooks();
      setPlaybooks(rows);
      if (!selectedPlaybookId && rows.length) {
        setSelectedPlaybookId(rows[0].id);
      }
    } finally {
      setLoading(false);
    }
  };

  const loadExecutions = async (playbookId: number) => {
    setExecLoading(true);
    try {
      const data = await fetchPlaybookExecutions(playbookId, 1, 20);
      setExecutions(data.executions || []);
    } finally {
      setExecLoading(false);
    }
  };

  const openCreate = () => {
    setEditingId(null);
    setForm({
      name: '',
      description: '',
      trigger_severities: 'HIGH, CRITICAL',
      trigger_rule_ids: '',
      trigger_event_types: 'signature, anomaly',
      enabled: true,
      actions: JSON.stringify(ACTION_TEMPLATES, null, 2),
    });
    setShowEditor(true);
  };

  const openEdit = (pb: Playbook) => {
    setEditingId(pb.id);
    setForm({
      name: pb.name,
      description: pb.description || '',
      trigger_severities: (pb.trigger_severities || []).join(', '),
      trigger_rule_ids: (pb.trigger_rule_ids || []).join(', '),
      trigger_event_types: (pb.trigger_event_types || []).join(', '),
      enabled: pb.enabled,
      actions: JSON.stringify(pb.actions || [], null, 2),
    });
    setShowEditor(true);
  };

  const parseCsvStrings = (value: string) =>
    value
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean);

  const parseCsvNumbers = (value: string) =>
    value
      .split(',')
      .map((v) => Number(v.trim()))
      .filter((v) => Number.isFinite(v) && v > 0);

  const savePlaybook = async () => {
    setMessage('');
    let actions: Array<Record<string, any>>;
    try {
      actions = JSON.parse(form.actions || '[]');
      if (!Array.isArray(actions)) {
        throw new Error('Actions must be a JSON array');
      }
    } catch (err: any) {
      setMessage(`Invalid actions JSON: ${err.message}`);
      return;
    }

    const payload = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      trigger_severities: parseCsvStrings(form.trigger_severities).map((v) => v.toUpperCase()),
      trigger_rule_ids: parseCsvNumbers(form.trigger_rule_ids),
      trigger_event_types: parseCsvStrings(form.trigger_event_types).map((v) => v.toLowerCase()),
      enabled: form.enabled,
      actions,
    };
    if (!payload.name) {
      setMessage('Name is required.');
      return;
    }

    if (editingId) {
      const updated = await updatePlaybook(editingId, payload);
      setPlaybooks((prev) => prev.map((p) => (p.id === editingId ? updated : p)));
      setSelectedPlaybookId(updated.id);
      setMessage('Playbook updated.');
    } else {
      const created = await createPlaybook(payload);
      setPlaybooks((prev) => [created, ...prev]);
      setSelectedPlaybookId(created.id);
      setMessage('Playbook created.');
    }
    setShowEditor(false);
  };

  const runTest = async (playbookId: number) => {
    setMessage('');
    try {
      const sample = JSON.parse(testPayload || '{}');
      const result = await testPlaybook(playbookId, sample);
      setMessage(`Test run: ${result.summary?.success ?? 0} success, ${result.summary?.failed ?? 0} failed`);
      await loadExecutions(playbookId);
      await loadPlaybooks();
    } catch (err: any) {
      setMessage(`Test failed: ${err?.response?.data?.detail || err.message}`);
    }
  };

  const onToggle = async (playbookId: number) => {
    const updated = await togglePlaybook(playbookId);
    setPlaybooks((prev) => prev.map((p) => (p.id === playbookId ? updated : p)));
  };

  const onDelete = async (playbookId: number) => {
    if (!confirm('Delete this playbook?')) return;
    await deletePlaybook(playbookId);
    const next = playbooks.filter((p) => p.id !== playbookId);
    setPlaybooks(next);
    if (selectedPlaybookId === playbookId) {
      setSelectedPlaybookId(next[0]?.id ?? null);
    }
  };

  return (
    <div className="nids-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="nids-title">Playbooks</h1>
          <p className="nids-subtitle">Automate response actions for events and cases with guarded execution.</p>
        </div>
        <button className="nids-btn-primary" onClick={openCreate}>
          <Plus className="w-4 h-4" />
          New Playbook
        </button>
      </div>

      {message && <div className="nids-card p-3 text-sm text-slate-300">{message}</div>}

      {showEditor && (
        <div className="nids-card p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input className="nids-input" placeholder="Name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
            <input className="nids-input" placeholder="Severity triggers (CSV)" value={form.trigger_severities} onChange={(e) => setForm((f) => ({ ...f, trigger_severities: e.target.value }))} />
            <input className="nids-input" placeholder="Rule IDs (CSV)" value={form.trigger_rule_ids} onChange={(e) => setForm((f) => ({ ...f, trigger_rule_ids: e.target.value }))} />
            <input className="nids-input" placeholder="Event types (CSV)" value={form.trigger_event_types} onChange={(e) => setForm((f) => ({ ...f, trigger_event_types: e.target.value }))} />
            <label className="flex items-center gap-2 text-slate-300">
              <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
              Enabled
            </label>
            <textarea className="nids-input md:col-span-2" rows={2} placeholder="Description" value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
            <textarea className="nids-input md:col-span-2" rows={8} placeholder="Actions JSON Array" value={form.actions} onChange={(e) => setForm((f) => ({ ...f, actions: e.target.value }))} />
          </div>
          <div className="flex gap-2">
            <button className="nids-btn-primary" onClick={savePlaybook}>Save</button>
            <button className="nids-btn-secondary" onClick={() => setShowEditor(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 nids-table-wrap">
          <table className="nids-table">
            <thead>
              <tr>
                <th className="nids-th">ID</th>
                <th className="nids-th">Name</th>
                <th className="nids-th">Enabled</th>
                <th className="nids-th">Success</th>
                <th className="nids-th">Failed</th>
                <th className="nids-th">Last Run</th>
                <th className="nids-th">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td className="nids-td" colSpan={7}>Loading playbooks...</td></tr>
              ) : playbooks.length === 0 ? (
                <tr><td className="nids-td" colSpan={7}>No playbooks configured.</td></tr>
              ) : (
                playbooks.map((pb) => (
                  <tr key={pb.id} className={clsx('nids-row', selectedPlaybookId === pb.id && 'bg-slate-800/50')} onClick={() => setSelectedPlaybookId(pb.id)}>
                    <td className="nids-td">#{pb.id}</td>
                    <td className="nids-td">
                      <div className="font-medium text-slate-100">{pb.name}</div>
                      <div className="text-xs text-slate-400">{pb.description || 'No description'}</div>
                    </td>
                    <td className="nids-td">{pb.enabled ? 'Yes' : 'No'}</td>
                    <td className="nids-td">{pb.success_count}</td>
                    <td className="nids-td">{pb.failure_count}</td>
                    <td className="nids-td">{pb.last_run_at ? format(new Date(pb.last_run_at), 'MMM dd, HH:mm') : '—'}</td>
                    <td className="nids-td">
                      <div className="flex items-center gap-2">
                        <button className="nids-btn-secondary !py-1 !px-2" onClick={(e) => { e.stopPropagation(); openEdit(pb); }}>
                          Edit
                        </button>
                        <button className="nids-btn-secondary !py-1 !px-2" onClick={(e) => { e.stopPropagation(); onToggle(pb.id); }}>
                          <Power className="w-4 h-4" />
                        </button>
                        <button className="nids-btn-secondary !py-1 !px-2" onClick={(e) => { e.stopPropagation(); runTest(pb.id); }}>
                          <Play className="w-4 h-4" />
                        </button>
                        <button className="nids-btn-secondary !py-1 !px-2 text-rose-300" onClick={(e) => { e.stopPropagation(); onDelete(pb.id); }}>
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="nids-card p-4 space-y-4">
          <h2 className="text-lg font-semibold text-slate-100">Execution Inspector</h2>
          {!selectedPlaybook ? (
            <div className="text-slate-400 text-sm">Select a playbook to inspect recent executions.</div>
          ) : (
            <>
              <div>
                <label className="nids-label">Test Payload (JSON)</label>
                <textarea className="nids-input" rows={5} value={testPayload} onChange={(e) => setTestPayload(e.target.value)} />
                <button className="nids-btn-primary mt-2 w-full" onClick={() => runTest(selectedPlaybook.id)}>Run Test</button>
              </div>
              <div className="space-y-2 max-h-80 overflow-auto">
                {execLoading ? (
                  <div className="text-slate-400 text-sm">Loading executions...</div>
                ) : executions.length === 0 ? (
                  <div className="text-slate-500 text-sm">No execution records yet.</div>
                ) : executions.map((e) => (
                  <div key={e.id} className="rounded-lg border border-slate-800 p-3">
                    <div className="flex items-center justify-between">
                      <div className="text-sm text-slate-100">{e.action}</div>
                      <span className={clsx('px-2 py-1 rounded-full text-xs font-semibold', STATUS_COLORS[e.status] || STATUS_COLORS.skipped)}>{e.status}</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      {format(new Date(e.created_at), 'MMM dd, HH:mm:ss')} • {e.actor_type}:{e.actor || 'system'}
                    </div>
                    {e.error_details && <div className="text-xs text-rose-300 mt-2">{e.error_details}</div>}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
