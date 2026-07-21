import { 
  Activity, AlertTriangle, Network, FileText, Shield, Bot,
  TrendingUp, TrendingDown, Minus, Clock, Users, Server
} from 'lucide-react';
import { cn, formatRelativeTime, getSeverityColor, getRiskLevel } from '../utils/cn';

const stats = [
  { name: 'Total Events', value: '12,345', change: '+12%', trend: 'up', icon: Activity, color: 'primary' },
  { name: 'Active Alerts', value: '23', change: '-5', trend: 'down', icon: AlertTriangle, color: 'danger' },
  { name: 'Network Connections', value: '1,234', change: '+8%', trend: 'up', icon: Network, color: 'success' },
  { name: 'Risk Score', value: '342', change: '+15', trend: 'up', icon: Shield, color: 'warning' },
];

const recentAlerts = [
  { id: 'ALT-001', title: 'Suspicious PowerShell Execution', severity: 'critical', time: '2 min ago', risk: 940 },
  { id: 'ALT-002', title: 'Unauthorized Network Connection', severity: 'high', time: '15 min ago', risk: 720 },
  { id: 'ALT-003', title: 'File Modification in System Directory', severity: 'medium', time: '1 hour ago', risk: 450 },
  { id: 'ALT-004', title: 'New Persistence Mechanism Detected', severity: 'high', time: '3 hours ago', risk: 680 },
  { id: 'ALT-005', title: 'Browser Extension Installed', severity: 'low', time: '5 hours ago', risk: 120 },
];

const topProcesses = [
  { name: 'powershell.exe', pid: 4521, events: 234, risk: 890, mitre: ['T1059.001'] },
  { name: 'cmd.exe', pid: 3210, events: 189, risk: 560, mitre: ['T1059.003'] },
  { name: 'wscript.exe', pid: 1102, events: 67, risk: 420, mitre: ['T1059.005'] },
  { name: 'rundll32.exe', pid: 5543, events: 45, risk: 380, mitre: ['T1218.011'] },
];

const mitreHeatmap = [
  { tactic: 'Initial Access', techniques: 3, risk: 720 },
  { tactic: 'Execution', techniques: 8, risk: 890 },
  { tactic: 'Persistence', techniques: 4, risk: 650 },
  { tactic: 'Privilege Escalation', techniques: 2, risk: 410 },
  { tactic: 'Defense Evasion', techniques: 5, risk: 580 },
  { tactic: 'Credential Access', techniques: 1, risk: 230 },
  { tactic: 'Discovery', techniques: 6, risk: 490 },
  { tactic: 'Lateral Movement', techniques: 0, risk: 0 },
  { tactic: 'Collection', techniques: 2, risk: 310 },
  { tactic: 'Command and Control', techniques: 3, risk: 540 },
  { tactic: 'Exfiltration', techniques: 1, risk: 180 },
  { tactic: 'Impact', techniques: 0, risk: 0 },
];

export default function Dashboard() {
  const overallRisk = getRiskLevel(342);
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400">Security overview and real-time monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className={cn(
            'flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium',
            overallRisk.color
          )}>
            <Shield className="h-4 w-4" />
            <span>Overall Risk: {overallRisk.label}</span>
          </div>
        </div>
      </div>
      
      {/* Stats Grid */}
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
                stat.trend === 'up' ? 'text-success-600 dark:text-success-400' : 'text-danger-600 dark:text-danger-400'
              )}>
                {stat.trend === 'up' ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                {stat.change}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400">vs last hour</span>
            </div>
          </div>
        ))}
      </div>
      
      {/* Main Content Grid */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column - Recent Alerts & Top Processes */}
        <div className="lg:col-span-2 space-y-6">
          {/* Recent Alerts */}
          <div className="card">
            <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Alerts</h2>
            </div>
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="px-6 py-3">Alert</th>
                    <th className="px-6 py-3">Severity</th>
                    <th className="px-6 py-3">Risk</th>
                    <th className="px-6 py-3">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {recentAlerts.map((alert) => {
                    const riskLevel = getRiskLevel(alert.risk);
                    return (
                      <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                        <td className="px-6 py-4">
                          <p className="font-medium text-gray-900 dark:text-white">{alert.title}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">{alert.id}</p>
                        </td>
                        <td className="px-6 py-4">
                          <span className={cn('badge', getSeverityColor(alert.severity))}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={cn('badge', riskLevel.color)}>
                            {alert.risk}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                          {alert.time}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          
          {/* Top Risky Processes */}
          <div className="card">
            <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Top Risky Processes</h2>
            </div>
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="px-6 py-3">Process</th>
                    <th className="px-6 py-3">PID</th>
                    <th className="px-6 py-3">Events</th>
                    <th className="px-6 py-3">Risk</th>
                    <th className="px-6 py-3">MITRE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {topProcesses.map((proc) => {
                    const riskLevel = getRiskLevel(proc.risk);
                    return (
                      <tr key={proc.pid} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                        <td className="px-6 py-4">
                          <p className="font-mono font-medium text-gray-900 dark:text-white">{proc.name}</p>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{proc.pid}</td>
                        <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{proc.events}</td>
                        <td className="px-6 py-4">
                          <span className={cn('badge', riskLevel.color)}>{proc.risk}</span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex flex-wrap gap-1">
                            {proc.mitre.map((t) => (
                              <span key={t} className="badge-gray text-xs">{t}</span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        
        {/* Right Column - MITRE Heatmap & Quick Stats */}
        <div className="space-y-6">
          {/* MITRE ATT&CK Heatmap */}
          <div className="card">
            <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Coverage</h2>
            </div>
            <div className="p-6 space-y-3">
              {mitreHeatmap.map((tactic) => (
                <div key={tactic.tactic} className="flex items-center gap-3">
                  <div className="w-40 text-sm font-medium text-gray-700 dark:text-gray-300">{tactic.tactic}</div>
                  <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div 
                      className="h-full rounded-full transition-all"
                      style={{ 
                        width: `${Math.min(tactic.risk / 10, 100)}%`,
                        backgroundColor: tactic.risk > 700 ? '#ef4444' : tactic.risk > 400 ? '#f59e0b' : tactic.risk > 100 ? '#3b82f6' : '#22c55e'
                      }}
                    />
                  </div>
                  <span className="w-16 text-right text-sm font-mono text-gray-500 dark:text-gray-400">
                    {tactic.techniques} tech
                  </span>
                </div>
              ))}
            </div>
          </div>
          
          {/* Quick Stats */}
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
                    <p className="font-medium text-gray-900 dark:text-white">2d 14h 32m</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-success-100 dark:bg-success-900/30">
                    <Users className="h-5 w-5 text-success-600 dark:text-success-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Monitored Users</p>
                    <p className="font-medium text-gray-900 dark:text-white">12</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30">
                    <Server className="h-5 w-5 text-amber-600 dark:text-amber-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Active Collectors</p>
                    <p className="font-medium text-gray-900 dark:text-white">7 / 7</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-100 dark:bg-purple-900/30">
                    <Bot className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">AI Explanations</p>
                    <p className="font-medium text-gray-900 dark:text-white">23 today</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}