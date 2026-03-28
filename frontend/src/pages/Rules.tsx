import { useEffect, useState } from 'react';
import { Power, Trash2, Edit2, Plus } from 'lucide-react';
import { fetchRules, toggleRule, deleteRule, createRule, updateRule, promoteRuleLifecycle } from '../lib/api';
import { Rule } from '../types';
import { format } from 'date-fns';
import clsx from 'clsx';

const RULE_TYPE_COLORS = {
  SIGNATURE: 'bg-blue-100 text-blue-800',
  RATE_LIMIT: 'bg-purple-100 text-purple-800',
  PAYLOAD_MATCH: 'bg-green-100 text-green-800',
  GEO_BLOCK: 'bg-orange-100 text-orange-800',
  WHITELIST: 'bg-gray-100 text-gray-800',
};

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showEditor, setShowEditor] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [form, setForm] = useState<any>({
    name: '',
    rule_type: 'SIGNATURE',
    criteria: {},
    description: '',
    priority: 'MEDIUM',
    lifecycle_state: 'production',
    mitre_tactics: '',
    mitre_techniques: '',
    suppression_enabled: false,
    suppression_window_seconds: 0,
  });

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      const data = await fetchRules();
      setRules(data);
    } catch (err) {
      console.error('Failed to load rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (ruleId: number) => {
    try {
      const updated = await toggleRule(ruleId);
      setRules(rules.map(r => r.id === ruleId ? updated : r));
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  const handleDelete = async (ruleId: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      await deleteRule(ruleId);
      setRules(rules.filter(r => r.id !== ruleId));
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  const parseList = (value: string) => value.split(',').map(v => v.trim()).filter(Boolean);

  const openCreate = () => {
    setEditingRule(null);
    setForm({
      name: '',
      rule_type: 'SIGNATURE',
      criteria: {},
      description: '',
      priority: 'MEDIUM',
      lifecycle_state: 'production',
      mitre_tactics: '',
      mitre_techniques: '',
      suppression_enabled: false,
      suppression_window_seconds: 0,
    });
    setShowEditor(true);
  };

  const openEdit = (rule: Rule) => {
    setEditingRule(rule);
    setForm({
      name: rule.name,
      rule_type: rule.rule_type,
      criteria: rule.criteria || {},
      description: (rule as any).description || '',
      priority: (rule as any).priority || 'MEDIUM',
      lifecycle_state: rule.lifecycle_state || 'production',
      mitre_tactics: (rule.mitre_tactics || []).join(', '),
      mitre_techniques: (rule.mitre_techniques || []).join(', '),
      suppression_enabled: !!rule.suppression_enabled,
      suppression_window_seconds: rule.suppression_window_seconds || 0,
    });
    setShowEditor(true);
  };

  const saveRule = async () => {
    const payload = {
      name: form.name,
      rule_type: form.rule_type,
      criteria: form.criteria,
      description: form.description || null,
      priority: form.priority,
      lifecycle_state: form.lifecycle_state,
      mitre_tactics: parseList(form.mitre_tactics),
      mitre_techniques: parseList(form.mitre_techniques),
      suppression_enabled: !!form.suppression_enabled,
      suppression_window_seconds: Number(form.suppression_window_seconds) || 0,
    };
    try {
      if (editingRule) {
        const updated = await updateRule(editingRule.id, payload);
        setRules(prev => prev.map(r => (r.id === editingRule.id ? updated : r)));
      } else {
        const created = await createRule(payload);
        setRules(prev => [...prev, created]);
      }
      setShowEditor(false);
    } catch (err) {
      console.error('Failed to save rule:', err);
    }
  };

  const lifecycleBadgeColor = (state: string) => {
    if (state === 'draft') return 'bg-slate-200 text-slate-800';
    if (state === 'staging') return 'bg-indigo-100 text-indigo-800';
    return 'bg-emerald-100 text-emerald-800';
  };

  if (loading) {
    return <div className="flex items-center justify-center h-96">Loading rules...</div>;
  }

  return (
    <div className="nids-page">
      <div className="flex items-center justify-between">
        <h1 className="nids-title">Detection Rules</h1>
        <button className="nids-btn-primary" onClick={openCreate}>
          <Plus className="w-4 h-4" />
          Add Rule
        </button>
      </div>

      {showEditor && (
        <div className="nids-card p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input className="nids-input" placeholder="Rule name" value={form.name} onChange={(e) => setForm((f: any) => ({ ...f, name: e.target.value }))} />
            <select className="nids-input" value={form.rule_type} onChange={(e) => setForm((f: any) => ({ ...f, rule_type: e.target.value }))}>
              <option value="SIGNATURE">SIGNATURE</option>
              <option value="RATE_LIMIT">RATE_LIMIT</option>
              <option value="PAYLOAD_MATCH">PAYLOAD_MATCH</option>
              <option value="GEO_BLOCK">GEO_BLOCK</option>
              <option value="WHITELIST">WHITELIST</option>
            </select>
            <select className="nids-input" value={form.lifecycle_state} onChange={(e) => setForm((f: any) => ({ ...f, lifecycle_state: e.target.value }))}>
              <option value="draft">draft</option>
              <option value="staging">staging</option>
              <option value="production">production</option>
            </select>
            <input className="nids-input" type="number" min={0} placeholder="Suppression window seconds" value={form.suppression_window_seconds} onChange={(e) => setForm((f: any) => ({ ...f, suppression_window_seconds: Number(e.target.value) }))} />
            <input className="nids-input md:col-span-2" placeholder="MITRE tactics (comma-separated)" value={form.mitre_tactics} onChange={(e) => setForm((f: any) => ({ ...f, mitre_tactics: e.target.value }))} />
            <input className="nids-input md:col-span-2" placeholder="MITRE techniques (comma-separated, e.g. T1110)" value={form.mitre_techniques} onChange={(e) => setForm((f: any) => ({ ...f, mitre_techniques: e.target.value }))} />
            <label className="flex items-center gap-2 text-slate-300">
              <input type="checkbox" checked={form.suppression_enabled} onChange={(e) => setForm((f: any) => ({ ...f, suppression_enabled: e.target.checked }))} />
              Suppression enabled
            </label>
            <textarea className="nids-input md:col-span-2" rows={4} placeholder='Criteria JSON, e.g. {"protocol":"tcp"}' value={JSON.stringify(form.criteria)} onChange={(e) => {
              try {
                const parsed = JSON.parse(e.target.value || '{}');
                setForm((f: any) => ({ ...f, criteria: parsed }));
              } catch {
                // keep user typing without breaking state
              }
            }} />
          </div>
          <div className="flex gap-2 mt-3">
            <button className="nids-btn-primary" onClick={saveRule}>Save</button>
            <button className="nids-btn-secondary" onClick={() => setShowEditor(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className={clsx(
              'nids-card p-6 border-l-4',
              rule.enabled ? 'border-emerald-500' : 'border-slate-700'
            )}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="text-lg font-semibold text-slate-100">{rule.name}</h3>
                  <span className={clsx('px-2 py-1 text-xs font-semibold rounded-full', RULE_TYPE_COLORS[rule.rule_type])}>
                    {rule.rule_type}
                  </span>
                  <span className={clsx(
                    'px-2 py-1 text-xs font-semibold rounded-full',
                    rule.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                    rule.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                    rule.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-green-100 text-green-800'
                  )}>
                    {rule.severity}
                  </span>
                  <span className={clsx('px-2 py-1 text-xs font-semibold rounded-full', lifecycleBadgeColor(rule.lifecycle_state || 'production'))}>
                    {rule.lifecycle_state || 'production'}
                  </span>
                </div>

                {!!rule.mitre_techniques?.length && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {rule.mitre_techniques.map((tech) => (
                      <span key={tech} className="px-2 py-1 text-xs rounded-full bg-fuchsia-100 text-fuchsia-800">
                        {tech}
                      </span>
                    ))}
                  </div>
                )}
                {!!rule.mitre_tactics?.length && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {rule.mitre_tactics.map((tactic) => (
                      <span key={tactic} className="px-2 py-1 text-xs rounded-full bg-sky-100 text-sky-800">
                        {tactic}
                      </span>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-2 gap-4 text-sm text-slate-400 mt-4">
                  <div>
                    <span className="font-medium">Version:</span> {rule.version}
                  </div>
                  <div>
                    <span className="font-medium">Hit Count:</span> {rule.hit_count || 0}
                  </div>
                  {rule.last_matched && (
                    <div className="col-span-2">
                      <span className="font-medium">Last Matched:</span> {format(new Date(rule.last_matched), 'MMM dd, yyyy HH:mm:ss')}
                    </div>
                  )}
                </div>

                <div className="mt-4 p-3 bg-slate-950/40 rounded-xl text-sm border border-slate-800">
                  <pre className="whitespace-pre-wrap text-slate-300">{JSON.stringify(rule.criteria, null, 2)}</pre>
                </div>
              </div>

              <div className="flex gap-2 ml-4">
                <button
                  onClick={() => handleToggle(rule.id)}
                  className={clsx(
                    'p-2 rounded-xl transition-colors',
                    rule.enabled
                      ? 'bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  )}
                  title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                >
                  <Power className="w-5 h-5" />
                </button>
                <button
                  onClick={() => openEdit(rule)}
                  className="p-2 bg-cyan-500/15 text-cyan-300 rounded-xl hover:bg-cyan-500/25 transition-colors"
                  title="Edit rule"
                >
                  <Edit2 className="w-5 h-5" />
                </button>
                <select
                  className="bg-slate-900 text-slate-200 border border-slate-700 rounded-xl px-2 py-1 text-xs"
                  value={rule.lifecycle_state || 'production'}
                  onChange={async (e) => {
                    try {
                      const updated = await promoteRuleLifecycle(rule.id, e.target.value as any);
                      setRules(prev => prev.map(r => (r.id === rule.id ? updated : r)));
                    } catch (err) {
                      console.error('Failed to promote lifecycle:', err);
                    }
                  }}
                >
                  <option value="draft">draft</option>
                  <option value="staging">staging</option>
                  <option value="production">production</option>
                </select>
                <button
                  onClick={() => handleDelete(rule.id)}
                  className="p-2 bg-rose-500/15 text-rose-300 rounded-xl hover:bg-rose-500/25 transition-colors"
                  title="Delete rule"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {rules.length === 0 && (
        <div className="text-center py-12 text-slate-500">
          No rules configured. Add your first detection rule to get started.
        </div>
      )}
    </div>
  );
}
