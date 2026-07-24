import { useQuery } from '@tanstack/react-query';
import { AlertTriangle } from 'lucide-react';
import { cn, formatRelativeTime, getSeverityColor, getRiskLevel } from '../utils/cn';
import * as api from '../utils/tauriApi';

export default function Alerts() {
  const alerts = useQuery({
    queryKey: ['alerts-page'],
    queryFn: () => api.getAlerts({ limit: 200 }),
    refetchInterval: 5000,
  });

  const items = alerts.data?.alerts ?? [];
  const newCount = items.filter((a) => a.state === 'new').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Alerts</h1>
          <p className="text-gray-500 dark:text-gray-400">
            {newCount > 0 ? `${newCount} new, ` : ''}{items.length} total
          </p>
        </div>
      </div>
      <div className="card">
        <div className="table-container">
          {items.length === 0 ? (
            <div className="p-12 text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-success-100 dark:bg-success-900/30">
                <AlertTriangle className="h-6 w-6 text-success-600 dark:text-success-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">No alerts</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Your system appears clean. No security alerts detected.
              </p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="px-6 py-3">Alert</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Risk</th>
                  <th className="px-6 py-3">State</th>
                  <th className="px-6 py-3">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {items.map((alert) => {
                  const riskLevel = getRiskLevel(alert.risk_score);
                  const severityStr = typeof alert.severity === 'string' ? alert.severity : `Level ${alert.severity}`;
                  return (
                    <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-6 py-4">
                        <p className="font-medium text-gray-900 dark:text-white">{alert.rule_id.replace(/_/g, ' ')}</p>
                        <p className="text-xs font-mono text-gray-400">{alert.id}</p>
                      </td>
                      <td className="px-6 py-4">
                        <span className={cn('badge', getSeverityColor(severityStr))}>{severityStr}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={cn('badge', riskLevel.color)}>{alert.risk_score}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={cn('badge', alert.state === 'new'
                          ? 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300'
                          : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200')}>{alert.state}</span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                        {formatRelativeTime(alert.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
