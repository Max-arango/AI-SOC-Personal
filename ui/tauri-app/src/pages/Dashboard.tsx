import { useQuery } from '@tanstack/react-query';
import {
  Activity, AlertTriangle, Network, Shield, Bot,
  TrendingUp, Clock, Users, Server,
} from 'lucide-react';
import { cn, formatRelativeTime, getSeverityColor, getRiskLevel } from '../utils/cn';
import * as api from '../utils/tauriApi';
import ProcessTree from '../components/ProcessTree';
import RiskTimeline from '../components/RiskTimeline';
import MitreHeatmap from '../components/MitreHeatmap';
import NetworkMap from '../components/NetworkMap';

export default function Dashboard() {
  const health = useQuery({ queryKey: ['health'], queryFn: api.getHealth, refetchInterval: 30000 });
  const status = useQuery({ queryKey: ['status'], queryFn: api.getStatus, refetchInterval: 10000 });
  const events = useQuery({
    queryKey: ['events'],
    queryFn: () => api.queryEvents({ limit: 100 }),
    refetchInterval: 5000,
  });
  const alerts = useQuery({
    queryKey: ['alerts'],
    queryFn: () => api.getAlerts({ limit: 100 }),
    refetchInterval: 5000,
  });
  const processes = useQuery({
    queryKey: ['processes'],
    queryFn: () => api.getProcesses({ limit: 200 }),
    refetchInterval: 10000,
  });
  const processTree = useQuery({
    queryKey: ['process-tree'],
    queryFn: api.getProcessTree,
    refetchInterval: 15000,
  });
  const riskTimeline = useQuery({
    queryKey: ['risk-timeline'],
    queryFn: () => api.getRiskTimeline(6),
    refetchInterval: 30000,
  });
  const mitreHeatmap = useQuery({
    queryKey: ['mitre-heatmap'],
    queryFn: api.getMitreHeatmap,
    refetchInterval: 60000,
  });
  const networkGraph = useQuery({
    queryKey: ['network-graph'],
    queryFn: api.getNetworkGraph,
    refetchInterval: 30000,
  });

  const eventCount = events.data?.total_count ?? 0;
  const alertCount = alerts.data?.total_count ?? 0;
  const topProcesses = processes.data?.processes ?? [];
  const recentAlerts = alerts.data?.alerts.slice(0, 5) ?? [];

  const activeAlertCount = alerts.data?.alerts.filter(
    (a) => a.state === 'new' || a.state === 'acknowledged',
  ).length ?? 0;

  const stats = [
    {
      name: 'Total Events', value: eventCount.toLocaleString(), change: '+0%', trend: 'neutral' as const,
      icon: Activity, color: 'primary',
    },
    {
      name: 'Active Alerts', value: String(activeAlertCount), change: 'live', trend: 'up' as const,
      icon: AlertTriangle, color: 'danger',
    },
    {
      name: 'Running Processes', value: String(topProcesses.length), change: 'live', trend: 'up' as const,
      icon: Network, color: 'success',
    },
    {
      name: 'System Status', value: health.data?.status ?? '...', change: '', trend: 'neutral' as const,
      icon: Shield, color: 'warning',
    },
  ];

  const safeAlerts = recentAlerts.map((a) => ({
    ...a,
    title: a.rule_id.replace('_', ' '),
    time: formatRelativeTime(a.created_at),
  }));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400">Security overview and real-time monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className={cn(
            'flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium',
            alertCount > 0
              ? 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300'
              : 'bg-success-100 text-success-800 dark:bg-success-900/30 dark:text-success-300',
          )}>
            <Shield className="h-4 w-4" />
            <span>{alertCount > 0 ? `${alertCount} alerts` : 'No alerts'}</span>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.name} className="card p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">{stat.name}</p>
                <p className="mt-1 text-3xl font-bold text-gray-900 dark:text-white">{stat.value}</p>
              </div>
              <div className={cn('flex h-12 w-12 items-center justify-center rounded-xl', `bg-${stat.color}-100 dark:bg-${stat.color}-900/30`)}>
                <stat.icon className={cn('h-6 w-6', `text-${stat.color}-600 dark:text-${stat.color}-400`)} />
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2">
              <span className={cn(
                'text-sm font-medium',
                stat.trend === 'up' ? 'text-success-600 dark:text-success-400' : 'text-gray-500',
              )}>
                {stat.trend === 'up' ? <TrendingUp className="h-4 w-4 inline" /> : null}
                {' '}{stat.change}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <div className="card">
            <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Alerts</h2>
            </div>
            <div className="table-container">
              {safeAlerts.length === 0 ? (
                <div className="p-12 text-center">
                  <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-success-100 dark:bg-success-900/30">
                    <Shield className="h-6 w-6 text-success-600 dark:text-success-400" />
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">No alerts detected</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Your system is clean. Alerts will appear here when suspicious activity is detected.
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
                    {safeAlerts.map((alert) => {
                      const riskLevel = getRiskLevel(alert.risk_score);
                      const severityStr = typeof alert.severity === 'string' ? alert.severity : `Level ${alert.severity}`;
                      return (
                        <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                          <td className="px-6 py-4">
                            <p className="font-medium text-gray-900 dark:text-white">{alert.title}</p>
                            <p className="text-sm text-gray-500 dark:text-gray-400">{alert.id}</p>
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
                          <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{alert.time}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="card">
            <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Running Processes</h2>
            </div>
            <div className="table-container">
              {topProcesses.length === 0 ? (
                <div className="p-12 text-center">
                  <p className="text-gray-500 dark:text-gray-400">Loading process data...</p>
                </div>
              ) : (
                <table className="table">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700">
                      <th className="px-6 py-3">Process</th>
                      <th className="px-6 py-3">PID</th>
                      <th className="px-6 py-3">CPU</th>
                      <th className="px-6 py-3">Memory</th>
                      <th className="px-6 py-3">User</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {topProcesses.slice(0, 10).map((proc) => {
                      const memMB = Math.round(proc.memory_bytes / 1024 / 1024);
                      return (
                        <tr key={`${proc.pid}-${proc.name}`} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                          <td className="px-6 py-4">
                            <p className="font-mono font-medium text-gray-900 dark:text-white">{proc.name}</p>
                            {proc.cmd && (
                              <p className="text-xs text-gray-400 dark:text-gray-500 truncate max-w-xs">{proc.cmd}</p>
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{proc.pid}</td>
                          <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{proc.cpu_usage.toFixed(1)}%</td>
                          <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{memMB} MB</td>
                          <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{proc.user_id ?? '-'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Statistics</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary-100 dark:bg-primary-900/30">
                    <Clock className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Uptime</p>
                    <p className="font-medium text-gray-900 dark:text-white">{status.data?.uptime ?? '...'}</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-success-100 dark:bg-success-900/30">
                    <Users className="h-5 w-5 text-success-600 dark:text-success-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Total Events</p>
                    <p className="font-medium text-gray-900 dark:text-white">{eventCount.toLocaleString()}</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30">
                    <Server className="h-5 w-5 text-amber-600 dark:text-amber-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Running Processes</p>
                    <p className="font-medium text-gray-900 dark:text-white">{topProcesses.length.toLocaleString()}</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={cn(
                    'flex h-10 w-10 items-center justify-center rounded-lg',
                    health.data?.status === 'healthy'
                      ? 'bg-success-100 dark:bg-success-900/30'
                      : 'bg-danger-100 dark:bg-danger-900/30',
                  )}>
                    <Bot className={cn(
                      'h-5 w-5',
                      health.data?.status === 'healthy'
                        ? 'text-success-600 dark:text-success-400'
                        : 'text-danger-600 dark:text-danger-400',
                    )} />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">System Health</p>
                    <p className="font-medium text-gray-900 dark:text-white capitalize">{health.data?.status ?? '...'}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="card p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Component Status</h3>
            <div className="space-y-2">
              {health.data?.components ? Object.entries(health.data.components).map(([name, state]) => (
                <div key={name} className="flex items-center justify-between">
                  <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">{name.replace('_', ' ')}</span>
                  <span className={cn(
                    'badge text-xs',
                    state === 'healthy'
                      ? 'bg-success-100 text-success-800 dark:bg-success-900/30 dark:text-success-300'
                      : 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
                  )}>{state}</span>
                </div>
              )) : (
                <p className="text-sm text-gray-400">Loading...</p>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card overflow-hidden">
          <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Process Tree</h2>
          </div>
          <ProcessTree data={{ nodes: (processTree.data?.tree?.nodes ?? []) as any }} />
        </div>
        <div className="card p-4">
          <div className="border-b border-gray-200 px-2 pb-4 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Risk Timeline (6h)</h2>
          </div>
          <RiskTimeline data={riskTimeline.data?.points ?? []} />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card p-4">
          <div className="border-b border-gray-200 px-2 pb-4 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Coverage</h2>
          </div>
          <MitreHeatmap data={mitreHeatmap.data?.tactics ?? []} />
        </div>
        <div className="card overflow-hidden">
          <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Network Map</h2>
          </div>
          <NetworkMap data={networkGraph.data ?? { nodes: [], edges: [] }} />
        </div>
      </div>
    </div>
  );
}
