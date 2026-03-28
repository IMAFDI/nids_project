import { useEffect, useMemo, useState } from 'react';
import {
  createRetentionPolicy,
  deleteRetentionPolicy,
  executeRetentionMaintenance,
  fetchBackupHistory,
  fetchRetentionPolicies,
  fetchSLOHistory,
  fetchSLOSummary,
  runBackupRestoreTest,
  runRetentionDryRun,
  startBackup,
  updateRetentionPolicy,
} from '../lib/api';
import { BackupOperation, RetentionPolicy, SLOSnapshot, SLOSummary } from '../types';
import { Activity, Archive, DatabaseBackup, Gauge, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';

const defaultForm = {
  name: '',
  scope: 'global' as 'global' | 'severity' | 'tenant',
  severity: '',
  hot_days: 7,
  warm_days: 30,
  cold_days: 90,
  delete_after_days: 365,
  archive_enabled: true,
  enabled: true,
};

export default function OpsPlatform() {
  const [policies, setPolicies] = useState<RetentionPolicy[]>([]);
  const [dryRun, setDryRun] = useState<{ evaluated_events: number; archive_candidates: number; delete_candidates: number } | null>(null);
  const [slo, setSlo] = useState<SLOSummary | null>(null);
  const [sloHistory, setSloHistory] = useState<SLOSnapshot[]>([]);
  const [backupHistory, setBackupHistory] = useState<BackupOperation[]>([]);
  const [form, setForm] = useState(defaultForm);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const loadData = async () => {
    try {
      const [policyData, dryRunData, sloData, sloHistoryData, backupData] = await Promise.all([
        fetchRetentionPolicies(),
        runRetentionDryRun(),
        fetchSLOSummary(),
        fetchSLOHistory(24),
        fetchBackupHistory(),
      ]);
      setPolicies(policyData);
      setDryRun(dryRunData);
      setSlo(sloData);
      setSloHistory(sloHistoryData);
      setBackupHistory(backupData);
    } catch (err) {
      setMessage('Failed to load platform operations data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const queueDepthPoints = useMemo(() => {
    return sloHistory.slice().reverse().map((item, idx) => ({
      x: idx,
      value: item.queue_depth,
    }));
  }, [sloHistory]);

  const createPolicy = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await createRetentionPolicy({
        ...form,
        severity: form.scope === 'severity' ? form.severity || 'MEDIUM' : undefined,
      });
      setForm(defaultForm);
      await loadData();
      setMessage('Retention policy created');
    } catch (err) {
      setMessage('Failed to create policy');
    } finally {
      setBusy(false);
    }
  };

  const togglePolicy = async (policy: RetentionPolicy) => {
    setBusy(true);
    try {
      await updateRetentionPolicy(policy.id, { enabled: !policy.enabled });
      await loadData();
    } finally {
      setBusy(false);
    }
  };

  const removePolicy = async (policyId: number) => {
    setBusy(true);
    try {
      await deleteRetentionPolicy(policyId);
      await loadData();
    } finally {
      setBusy(false);
    }
  };

  const executeRetention = async (applyDelete: boolean) => {
    setBusy(true);
    setMessage(null);
    try {
      await executeRetentionMaintenance({ apply_delete: applyDelete, confirm_delete: applyDelete && confirmDelete });
      await loadData();
      setMessage(applyDelete ? 'Retention maintenance executed with deletion' : 'Retention maintenance executed');
    } catch (err) {
      setMessage('Retention execution failed (check delete confirmation)');
    } finally {
      setBusy(false);
    }
  };

  const triggerBackup = async () => {
    setBusy(true);
    try {
      await startBackup({ target: 'database', dry_run: true });
      await loadData();
      setMessage('Backup runbook stub started');
    } finally {
      setBusy(false);
    }
  };

  const triggerRestoreTest = async () => {
    setBusy(true);
    try {
      await runBackupRestoreTest({ dry_run: true });
      await loadData();
      setMessage('Restore test runbook stub executed');
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return <div className="text-slate-400">Loading platform operations...</div>;
  }

  return (
    <div className="nids-page space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="nids-title">Platform & Ops</h1>
        <button onClick={loadData} className="nids-btn-secondary">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {message && <div className="bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 px-4 py-3 rounded-xl">{message}</div>}

      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Kpi title="Ingestion Availability" value={`${slo?.ingestion_availability ?? 0}%`} icon={ShieldCheck} />
        <Kpi title="Latency p95" value={`${slo?.event_processing_latency_ms.p95 ?? 0}ms`} icon={Gauge} />
        <Kpi title="Queue Depth" value={`${slo?.queue_depth_trend.current ?? 0}`} icon={Activity} />
        <Kpi title="Error Budget" value={`${slo?.error_budget_remaining ?? 0}%`} icon={Archive} />
      </section>

      <section className="nids-card p-6">
        <h2 className="text-lg font-semibold text-slate-100 mb-4">SLO Snapshot</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="text-slate-300">Broker: <span className="font-semibold text-slate-100">{slo?.connectivity.broker}</span></div>
          <div className="text-slate-300">Database: <span className="font-semibold text-slate-100">{slo?.connectivity.database}</span></div>
          <div className="text-slate-300">Cache: <span className="font-semibold text-slate-100">{slo?.connectivity.cache}</span></div>
        </div>
        <div className="mt-4">
          <h3 className="text-sm text-slate-400 mb-2">Queue Trend (latest snapshots)</h3>
          <div className="flex items-end gap-1 h-20">
            {queueDepthPoints.map((p) => (
              <div key={p.x} className="bg-cyan-500/40 rounded-t w-2" style={{ height: `${Math.min(100, p.value)}%` }} />
            ))}
          </div>
        </div>
      </section>

      <section className="nids-card p-6 space-y-4">
        <h2 className="text-lg font-semibold text-slate-100">Retention Policies</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="nids-input" placeholder="Policy name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <select className="nids-input" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as any })}>
            <option value="global">global</option>
            <option value="severity">severity</option>
            <option value="tenant">tenant</option>
          </select>
          <input className="nids-input" placeholder="Severity (if scope=severity)" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} />
          <input className="nids-input" type="number" value={form.hot_days} onChange={(e) => setForm({ ...form, hot_days: Number(e.target.value) })} />
          <input className="nids-input" type="number" value={form.warm_days} onChange={(e) => setForm({ ...form, warm_days: Number(e.target.value) })} />
          <input className="nids-input" type="number" value={form.cold_days} onChange={(e) => setForm({ ...form, cold_days: Number(e.target.value) })} />
          <input className="nids-input" type="number" value={form.delete_after_days} onChange={(e) => setForm({ ...form, delete_after_days: Number(e.target.value) })} />
          <label className="text-sm text-slate-300 flex items-center gap-2"><input type="checkbox" checked={form.archive_enabled} onChange={(e) => setForm({ ...form, archive_enabled: e.target.checked })} />Archive enabled</label>
          <button className="nids-btn-primary" onClick={createPolicy} disabled={busy}>Create Policy</button>
        </div>

        <div className="text-sm text-slate-300">
          Dry-run: evaluate <strong>{dryRun?.evaluated_events ?? 0}</strong>, archive <strong>{dryRun?.archive_candidates ?? 0}</strong>, delete <strong>{dryRun?.delete_candidates ?? 0}</strong>
        </div>

        <div className="flex flex-wrap gap-3">
          <button className="nids-btn-secondary" onClick={() => executeRetention(false)} disabled={busy}>Run Maintenance (no delete)</button>
          <label className="text-sm text-slate-300 flex items-center gap-2">
            <input type="checkbox" checked={confirmDelete} onChange={(e) => setConfirmDelete(e.target.checked)} />
            Confirm delete
          </label>
          <button className="nids-btn-secondary" onClick={() => executeRetention(true)} disabled={busy}>Run Maintenance + Delete</button>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400 border-b border-slate-800">
                <th className="py-2">Name</th>
                <th>Scope</th>
                <th>Windows</th>
                <th>Delete After</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.id} className="border-b border-slate-900/80">
                  <td className="py-2 text-slate-200">{policy.name}</td>
                  <td className="text-slate-300">{policy.scope}{policy.severity ? `:${policy.severity}` : ''}</td>
                  <td className="text-slate-300">{policy.hot_days}/{policy.warm_days}/{policy.cold_days}</td>
                  <td className="text-slate-300">{policy.delete_after_days}d</td>
                  <td className="text-slate-300">{policy.enabled ? 'enabled' : 'disabled'}</td>
                  <td className="text-right">
                    <button className="mr-2 text-cyan-300" onClick={() => togglePolicy(policy)}>{policy.enabled ? 'Disable' : 'Enable'}</button>
                    <button className="text-rose-300" onClick={() => removePolicy(policy.id)}><Trash2 className="w-4 h-4 inline" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="nids-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-100">Backup / Restore Runbook Hooks</h2>
          <div className="flex gap-2">
            <button className="nids-btn-secondary" onClick={triggerBackup} disabled={busy}>
              <DatabaseBackup className="w-4 h-4" />
              Start Backup
            </button>
            <button className="nids-btn-secondary" onClick={triggerRestoreTest} disabled={busy}>Restore Test</button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400 border-b border-slate-800">
                <th className="py-2">Time</th>
                <th>Type</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Artifact</th>
              </tr>
            </thead>
            <tbody>
              {backupHistory.map((item) => (
                <tr key={item.id} className="border-b border-slate-900/80 text-slate-300">
                  <td className="py-2">{new Date(item.created_at).toLocaleString()}</td>
                  <td>{item.operation_type}</td>
                  <td>{item.status}</td>
                  <td>{item.duration_ms ?? 0}ms</td>
                  <td className="font-mono text-xs">{item.artifact_path ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Kpi({ title, value, icon: Icon }: { title: string; value: string; icon: typeof ShieldCheck }) {
  return (
    <div className="nids-kpi">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-400">{title}</p>
          <p className="text-2xl font-semibold text-slate-100">{value}</p>
        </div>
        <div className="p-3 rounded-full bg-cyan-500/20">
          <Icon className="w-5 h-5 text-cyan-300" />
        </div>
      </div>
    </div>
  );
}
