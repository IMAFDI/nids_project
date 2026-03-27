import { useEffect, useState } from 'react';
import { Power, Trash2, Edit2, Plus } from 'lucide-react';
import { fetchRules, toggleRule, deleteRule } from '../lib/api';
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

  if (loading) {
    return <div className="flex items-center justify-center h-96">Loading rules...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Detection Rules</h1>
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          <Plus className="w-4 h-4" />
          Add Rule
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className={clsx(
              'bg-white rounded-lg shadow p-6 border-l-4',
              rule.enabled ? 'border-green-500' : 'border-gray-300'
            )}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="text-lg font-semibold text-gray-900">{rule.name}</h3>
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
                </div>

                <div className="grid grid-cols-2 gap-4 text-sm text-gray-600 mt-4">
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

                <div className="mt-4 p-3 bg-gray-50 rounded text-sm">
                  <pre className="whitespace-pre-wrap text-gray-700">{JSON.stringify(rule.criteria, null, 2)}</pre>
                </div>
              </div>

              <div className="flex gap-2 ml-4">
                <button
                  onClick={() => handleToggle(rule.id)}
                  className={clsx(
                    'p-2 rounded-lg transition-colors',
                    rule.enabled
                      ? 'bg-green-100 text-green-700 hover:bg-green-200'
                      : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                  )}
                  title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                >
                  <Power className="w-5 h-5" />
                </button>
                <button
                  className="p-2 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors"
                  title="Edit rule"
                >
                  <Edit2 className="w-5 h-5" />
                </button>
                <button
                  onClick={() => handleDelete(rule.id)}
                  className="p-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 transition-colors"
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
        <div className="text-center py-12 text-gray-500">
          No rules configured. Add your first detection rule to get started.
        </div>
      )}
    </div>
  );
}
