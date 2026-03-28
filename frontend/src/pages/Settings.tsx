import { useState } from 'react';
import { Save, Mail, MessageSquare, AlertCircle } from 'lucide-react';

export default function Settings() {
  const [settings, setSettings] = useState({
    email: {
      enabled: false,
      host: 'smtp.gmail.com',
      port: 587,
      user: '',
      from: '',
      to: '',
    },
    slack: {
      enabled: false,
      webhook: '',
    },
    pagerduty: {
      enabled: false,
      routing_key: '',
    },
    teams: {
      enabled: false,
      webhook: '',
    },
    syslog: {
      enabled: false,
      host: 'localhost',
      port: 514,
      protocol: 'udp',
    },
  });

  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="nids-page max-w-5xl">
      <h1 className="nids-title">Settings</h1>

      {/* Email Settings */}
      <div className="nids-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Mail className="w-6 h-6 text-blue-600" />
          <h2 className="text-xl font-semibold text-slate-100">Email Notifications</h2>
        </div>

        <div className="space-y-4">
          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.email.enabled}
              onChange={(e) => setSettings({
                ...settings,
                email: { ...settings.email, enabled: e.target.checked }
              })}
              className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
            />
            <label className="ml-2 text-sm font-medium text-slate-300">Enable email notifications</label>
          </div>

          {settings.email.enabled && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-6">
              <div>
                <label className="nids-label">SMTP Host</label>
                <input
                  type="text"
                  value={settings.email.host}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, host: e.target.value }
                  })}
                  className="nids-input"
                />
              </div>
              <div>
                <label className="nids-label">Port</label>
                <input
                  type="number"
                  value={settings.email.port}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, port: parseInt(e.target.value) }
                  })}
                  className="nids-input"
                />
              </div>
              <div>
                <label className="nids-label">From Email</label>
                <input
                  type="email"
                  value={settings.email.from}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, from: e.target.value }
                  })}
                  className="nids-input"
                />
              </div>
              <div>
                <label className="nids-label">To Email</label>
                <input
                  type="email"
                  value={settings.email.to}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, to: e.target.value }
                  })}
                  className="nids-input"
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Slack Settings */}
      <div className="nids-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <MessageSquare className="w-6 h-6 text-purple-600" />
          <h2 className="text-xl font-semibold text-slate-100">Slack Notifications</h2>
        </div>

        <div className="space-y-4">
          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.slack.enabled}
              onChange={(e) => setSettings({
                ...settings,
                slack: { ...settings.slack, enabled: e.target.checked }
              })}
              className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
            />
            <label className="ml-2 text-sm font-medium text-slate-300">Enable Slack notifications</label>
          </div>

          {settings.slack.enabled && (
            <div className="pl-6">
              <label className="nids-label">Webhook URL</label>
              <input
                type="text"
                value={settings.slack.webhook}
                onChange={(e) => setSettings({
                  ...settings,
                  slack: { ...settings.slack, webhook: e.target.value }
                })}
                placeholder="https://hooks.slack.com/services/..."
                className="nids-input"
              />
            </div>
          )}
        </div>
      </div>

      {/* PagerDuty Settings */}
      <div className="nids-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="w-6 h-6 text-red-600" />
          <h2 className="text-xl font-semibold text-slate-100">PagerDuty (Critical Only)</h2>
        </div>

        <div className="space-y-4">
          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.pagerduty.enabled}
              onChange={(e) => setSettings({
                ...settings,
                pagerduty: { ...settings.pagerduty, enabled: e.target.checked }
              })}
              className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
            />
            <label className="ml-2 text-sm font-medium text-slate-300">Enable PagerDuty alerts</label>
          </div>

          {settings.pagerduty.enabled && (
            <div className="pl-6">
              <label className="nids-label">Routing Key</label>
              <input
                type="text"
                value={settings.pagerduty.routing_key}
                onChange={(e) => setSettings({
                  ...settings,
                  pagerduty: { ...settings.pagerduty, routing_key: e.target.value }
                })}
                placeholder="Enter your PagerDuty routing key"
                className="nids-input"
              />
            </div>
          )}
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="nids-btn-primary"
        >
          <Save className="w-5 h-5" />
          {saved ? 'Settings Saved!' : 'Save Settings'}
        </button>
      </div>

      {saved && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-xl">
          Settings have been saved successfully!
        </div>
      )}
    </div>
  );
}
