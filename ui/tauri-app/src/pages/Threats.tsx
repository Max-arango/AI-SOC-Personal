import { useQuery } from '@tanstack/react-query';
import { Shield } from 'lucide-react';
import * as api from '../utils/tauriApi';

export default function Threats() {
  const heatmap = useQuery({
    queryKey: ['mitre-heatmap-full'],
    queryFn: api.getMitreHeatmap,
    refetchInterval: 60000,
  });

  const tactics = heatmap.data?.tactics ?? [];
  const maxCount = Math.max(...tactics.map((t) => t.techniques_count), 1);
  const totalDetections = tactics.reduce((sum, t) => sum + t.techniques_count, 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threats</h1>
        <p className="text-gray-500 dark:text-gray-400">
          {heatmap.isLoading ? 'Loading...' : `${totalDetections} detections across ${tactics.filter(t => t.techniques_count > 0).length} tactics`}
        </p>
      </div>
      <div className="card">
        <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Coverage</h2>
        </div>
        <div className="p-6">
          {tactics.length === 0 ? (
            <div className="p-8 text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/30">
                <Shield className="h-6 w-6 text-amber-600 dark:text-amber-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">No threats detected</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                MITRE ATT&CK mapping will populate as detection rules fire.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {tactics.map((tactic) => {
                const width = (tactic.techniques_count / maxCount) * 100;
                const bgColor =
                  tactic.max_risk > 700 ? 'bg-red-500'
                  : tactic.max_risk > 400 ? 'bg-orange-500'
                  : tactic.max_risk > 100 ? 'bg-yellow-500'
                  : tactic.techniques_count > 0 ? 'bg-blue-500'
                  : 'bg-gray-200 dark:bg-gray-700';

                return (
                  <div key={tactic.tactic} className="flex items-center gap-3">
                    <div className="w-36 text-sm font-medium text-gray-700 dark:text-gray-300 truncate">
                      {tactic.tactic}
                    </div>
                    <div className="flex-1 h-5 bg-gray-100 dark:bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${bgColor}`}
                        style={{ width: `${Math.max(width, 2)}%` }}
                      />
                    </div>
                    <span className="w-12 text-right text-xs font-mono text-gray-500">
                      {tactic.techniques_count}
                    </span>
                    <span className="w-12 text-right text-xs font-mono text-gray-500">
                      {tactic.max_risk > 0 ? `${tactic.max_risk}` : '-'}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <div className="card p-4 text-center">
        <p className="text-lg font-bold text-gray-900 dark:text-white">{tactics.filter(t => t.techniques_count > 0).length} / {tactics.length}</p>
        <p className="text-sm text-gray-500">MITRE ATT&CK tactics with activity</p>
      </div>
    </div>
  );
}
