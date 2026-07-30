import { useQuery } from '@tanstack/react-query';
import { FileText, HardDrive } from 'lucide-react';
import { cn, formatRelativeTime, getSeverityColor } from '../utils/cn';
import * as api from '../utils/tauriApi';

export default function Files() {
  const events = useQuery({
    queryKey: ['file-events'],
    queryFn: () => api.queryEvents({ sources: ['file'], limit: 100 }),
    refetchInterval: 15000,
  });

  const items = events.data?.events ?? [];
  const fileEvents = items.filter((e: any) =>
    e.type?.includes('file')
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Files</h1>
        <p className="text-gray-500 dark:text-gray-400">
          {events.isLoading ? 'Loading...' : `${fileEvents.length} file events recorded`}
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-purple-600">{fileEvents.filter((e: any) => e.type?.includes('create')).length}</p>
          <p className="text-sm text-gray-500">Created</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-orange-600">{fileEvents.filter((e: any) => e.type?.includes('modify')).length}</p>
          <p className="text-sm text-gray-500">Modified</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-red-600">{fileEvents.filter((e: any) => e.type?.includes('delete')).length}</p>
          <p className="text-sm text-gray-500">Deleted</p>
        </div>
      </div>

      <div className="card">
        <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700 flex items-center gap-2">
          <FileText className="h-5 w-5 text-purple-500" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">File Activity</h2>
        </div>
        <div className="table-container">
          {fileEvents.length === 0 ? (
            <div className="p-12 text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900/30">
                <HardDrive className="h-6 w-6 text-purple-600 dark:text-purple-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">No file activity</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                File events will appear when the file collector detects changes.
              </p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="px-6 py-3">Action</th>
                  <th className="px-6 py-3">Path</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Risk</th>
                  <th className="px-6 py-3">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {fileEvents.map((evt: any) => (
                  <tr key={evt.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-6 py-4">
                      <span className={cn(
                        'badge',
                        evt.type?.includes('create') ? 'bg-green-100 text-green-800' :
                        evt.type?.includes('modify') ? 'bg-orange-100 text-orange-800' :
                        'bg-red-100 text-red-800'
                      )}>
                        {evt.type?.replace('sentinel.file.', '') ?? 'unknown'}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-sm text-gray-600 dark:text-gray-300 truncate max-w-xs">
                      {evt.payload?.path ?? evt.process?.path ?? '-'}
                    </td>
                    <td className="px-6 py-4">
                      <span className={cn('badge', getSeverityColor(String(evt.severity ?? 'info')))}>
                        {evt.severity ?? '-'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">{evt.risk_score ?? 0}</td>
                    <td className="px-6 py-4 text-xs text-gray-400">
                      {evt.timestamp ? formatRelativeTime(new Date((evt.timestamp as number) * 1000).toISOString()) : '-'}
                    </td>
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
