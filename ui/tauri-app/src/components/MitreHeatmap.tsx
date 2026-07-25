interface MitreTactic {
  tactic: string;
  id: string;
  techniques_count: number;
  max_risk: number;
}

export default function MitreHeatmap({ data }: { data: MitreTactic[] }) {
  if (!data?.length) {
    return (
      <div className="flex h-full items-center justify-center text-gray-400">
        <p>No MITRE data yet</p>
      </div>
    );
  }

  const maxCount = Math.max(...data.map((t) => t.techniques_count), 1);

  return (
    <div className="space-y-1.5">
      {data.map((tactic) => {
        const width = (tactic.techniques_count / maxCount) * 100;
        const bgColor =
          tactic.max_risk > 700
            ? 'bg-red-500'
            : tactic.max_risk > 400
            ? 'bg-orange-500'
            : tactic.max_risk > 100
            ? 'bg-yellow-500'
            : tactic.techniques_count > 0
            ? 'bg-blue-500'
            : 'bg-gray-200 dark:bg-gray-700';

        return (
          <div key={tactic.tactic} className="flex items-center gap-2">
            <div className="w-36 text-xs font-medium text-gray-700 dark:text-gray-300 truncate">
              {tactic.tactic}
            </div>
            <div className="flex-1 h-4 bg-gray-100 dark:bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${bgColor}`}
                style={{ width: `${Math.max(width, 2)}%` }}
              />
            </div>
            <span className="w-16 text-right text-xs font-mono text-gray-500">
              {tactic.techniques_count} det
            </span>
          </div>
        );
      })}
    </div>
  );
}
