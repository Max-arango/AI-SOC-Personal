import { useQuery } from '@tanstack/react-query';
import { Activity } from 'lucide-react';
import { cn, getSeverityColor } from '../utils/cn';
import * as api from '../utils/tauriApi';

export default function Events() {
  const events = useQuery({
    queryKey: ['events-page'],
    queryFn: () => api.queryEvents({ limit: 100 }),
    refetchInterval: 5000,
  });

  const items = events.data?.events ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Events</h1>
        <p className="text-gray-500 dark:text-gray-400">
          {events.isLoading ? 'Loading...' : `${events.data?.total_count ?? 0} events recorded`}
        </p>
      </div>
      <div className="card">
        <div className="table-container">
          {items.length === 0 ? (
            <div className="p-12 text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
                <Activity className="h-6 w-6 text-gray-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">No events yet</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Events will appear here when collectors detect system activity.
              </p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="px-6 py-3">Type</th>
                  <th className="px-6 py-3">Source</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Risk</th>
                  <th className="px-6 py-3">ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {items.map((evt: any) => (
                  <tr key={evt.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-6 py-4">
                      <p className="font-mono text-sm text-gray-900 dark:text-white">{evt.type ?? 'Unknown'}</p>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{evt.source ?? '-'}</td>
                    <td className="px-6 py-4">
                      <span className={cn('badge', getSeverityColor(String(evt.severity ?? 'info')))}>
                        {evt.severity ?? '-'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{evt.risk_score ?? 0}</td>
                    <td className="px-6 py-4 font-mono text-xs text-gray-400 dark:text-gray-500">{String(evt.id ?? '-').slice(0, 12)}...</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
