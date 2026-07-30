import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Settings as SettingsIcon, Save } from 'lucide-react';
import * as api from '../utils/tauriApi';

export default function Settings() {
  const [editing, setEditing] = useState(false);
  const [configText, setConfigText] = useState('');
  const [saving, setSaving] = useState(false);

  const config = useQuery({
    queryKey: ['config'],
    queryFn: async () => {
      const c = await api.getConfig();
      setConfigText(c.config_toml);
      return c;
    },
    refetchInterval: 30000,
  });

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateConfig(JSON.parse(configText));
      setEditing(false);
    } catch (e: any) {
      alert('Failed to save: ' + String(e));
    }
    setSaving(false);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
          <p className="text-gray-500 dark:text-gray-400">Configuration management</p>
        </div>
        <div className="flex gap-2">
          {editing ? (
            <>
              <button
                onClick={() => { setEditing(false); setConfigText(config.data?.config_toml ?? ''); }}
                className="rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-1.5 rounded-lg bg-primary-600 px-3 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
              >
                <Save className="h-4 w-4" />
                {saving ? 'Saving...' : 'Save'}
              </button>
            </>
          ) : (
            <button
              onClick={() => setEditing(true)}
              className="rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300"
            >
              Edit Config
            </button>
          )}
        </div>
      </div>
      <div className="card">
        <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700 flex items-center gap-2">
          <SettingsIcon className="h-5 w-5 text-gray-400" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Configuration</h2>
        </div>
        <div className="p-6">
          {config.isLoading ? (
            <div className="py-10 text-center text-gray-400">Loading config...</div>
          ) : editing ? (
            <textarea
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              className="w-full h-96 font-mono text-sm bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg p-4 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-primary-500"
              spellCheck={false}
            />
          ) : (
            <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 p-4">
              <pre className="text-xs font-mono text-gray-700 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto">
                {configText || 'No config loaded'}
              </pre>
            </div>
          )}
          <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
            Edit <code className="text-xs bg-gray-100 dark:bg-gray-700 px-1 rounded">~/.config/sentinel/config.toml</code> for persistent changes.
          </p>
        </div>
      </div>
    </div>
  );
}
