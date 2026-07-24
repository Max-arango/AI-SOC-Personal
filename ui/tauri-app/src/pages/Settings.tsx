import { useQuery } from '@tanstack/react-query';
import { Settings as SettingsIcon } from 'lucide-react';
import * as api from '../utils/tauriApi';

export default function Settings() {
  const config = useQuery({
    queryKey: ['config'],
    queryFn: api.getConfig,
    refetchInterval: 30000,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-500 dark:text-gray-400">Configuration management</p>
      </div>
      <div className="card">
        <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700 flex items-center gap-2">
          <SettingsIcon className="h-5 w-5 text-gray-400" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Configuration</h2>
        </div>
        <div className="p-6">
          <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 p-4">
            <pre className="text-xs font-mono text-gray-700 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap">
              {config.isLoading ? 'Loading...' : config.data?.config_toml ?? 'No config loaded'}
            </pre>
          </div>
          <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
            Edit the configuration file at <code className="text-xs bg-gray-100 dark:bg-gray-700 px-1 rounded">~/.config/sentinel/config.toml</code> for full customization.
          </p>
        </div>
      </div>
    </div>
  );
}
