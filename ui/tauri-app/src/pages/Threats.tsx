import { Shield } from 'lucide-react';

const mitreTactics = [
  { tactic: 'Initial Access', techniques: 0, risk: 0 },
  { tactic: 'Execution', techniques: 0, risk: 0 },
  { tactic: 'Persistence', techniques: 0, risk: 0 },
  { tactic: 'Privilege Escalation', techniques: 0, risk: 0 },
  { tactic: 'Defense Evasion', techniques: 0, risk: 0 },
  { tactic: 'Credential Access', techniques: 0, risk: 0 },
  { tactic: 'Discovery', techniques: 0, risk: 0 },
  { tactic: 'Lateral Movement', techniques: 0, risk: 0 },
  { tactic: 'Collection', techniques: 0, risk: 0 },
  { tactic: 'Command and Control', techniques: 0, risk: 0 },
  { tactic: 'Exfiltration', techniques: 0, risk: 0 },
  { tactic: 'Impact', techniques: 0, risk: 0 },
];

export default function Threats() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threats</h1>
        <p className="text-gray-500 dark:text-gray-400">MITRE ATT&CK detection coverage</p>
      </div>
      <div className="card">
        <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Coverage</h2>
        </div>
        <div className="p-6">
          <div className="p-8 text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/30">
              <Shield className="h-6 w-6 text-amber-600 dark:text-amber-400" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">No threats detected</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              MITRE ATT&CK mapping will populate as detection rules fire.
            </p>
          </div>
          <div className="space-y-3 mt-6">
            {mitreTactics.map((tactic) => (
              <div key={tactic.tactic} className="flex items-center gap-3">
                <div className="w-40 text-sm font-medium text-gray-700 dark:text-gray-300">
                  {tactic.tactic}
                </div>
                <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-green-500 transition-all"
                    style={{ width: '0%' }}
                  />
                </div>
                <span className="w-16 text-right text-sm font-mono text-gray-500 dark:text-gray-400">
                  {tactic.techniques} tech
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
