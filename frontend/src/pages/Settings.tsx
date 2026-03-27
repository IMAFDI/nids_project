import { useState, useEffect } from 'react';
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
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-3xl font-bold text-gray-900">Settings</h1>

      {/* Email Settings */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-4">
          <Mail className="w-6 h-6 text-blue-600" />
          <h2 className="text-xl font-semibold text-gray-900">Email Notifications</h2>
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
            <label className="ml-2 text-sm font-medium text-gray-700">Enable email notifications</label>
          </div>

          {settings.email.enabled && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">SMTP Host</label>
                <input
                  type="text"
                  value={settings.email.host}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, host: e.target.value }
                  })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
                <input
                  type="number"
                  value={settings.email.port}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, port: parseInt(e.target.value) }
                  })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">From Email</label>
                <input
                  type="email"
                  value={settings.email.from}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, from: e.target.value }
                  })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">To Email</label>
                <input
                  type="email"
                  value={settings.email.to}
                  onChange={(e) => setSettings({
                    ...settings,
                    email: { ...settings.email, to: e.target.value }
                  })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Slack Settings */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-4">
          <MessageSquare className="w-6 h-6 text-purple-600" />
          <h2 className="text-xl font-semibold text-gray-900">Slack Notifications</h2>
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
            <label className="ml-2 text-sm font-medium text-gray-700">Enable Slack notifications</label>
          </div>

          {settings.slack.enabled && (
            <div className="pl-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Webhook URL</label>
              <input
                type="text"
                value={settings.slack.webhook}
                onChange={(e) => setSettings({
                  ...settings,
                  slack: { ...settings.slack, webhook: e.target.value }
                })}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              />
            </div>
          )}
        </div>
      </div>

      {/* PagerDuty Settings */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="w-6 h-6 text-red-600" />
          <h2 className="text-xl font-semibold text-gray-900">PagerDuty (Critical Only)</h2>
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
            <label className="ml-2 text-sm font-medium text-gray-700">Enable PagerDuty alerts</label>
          </div>

          {settings.pagerduty.enabled && (
            <div className="pl-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Routing Key</label>
              <input
                type="text"
                value={settings.pagerduty.routing_key}
                onChange={(e) => setSettings({
                  ...settings,
                  pagerduty: { ...settings.pagerduty, routing_key: e.target.value }
                })}
                placeholder="Enter your PagerDuty routing key"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              />
            </div>
          )}
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Save className="w-5 h-5" />
          {saved ? 'Settings Saved!' : 'Save Settings'}
        </button>
      </div>

      {saved && (
        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
          Settings have been saved successfully!
        </div>
      )}
    </div>
  );
}
