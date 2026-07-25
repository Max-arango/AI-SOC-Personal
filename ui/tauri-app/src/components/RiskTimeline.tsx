import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Brush,
} from 'recharts';

interface TimelinePoint {
  timestamp: number;
  risk_score: number;
  event_type: string;
}

export default function RiskTimeline({ data }: { data: TimelinePoint[] }) {
  if (!data?.length) {
    return (
      <div className="flex h-full items-center justify-center text-gray-400">
        <p>Collecting risk data...</p>
      </div>
    );
  }

  const chartData = data.map((p) => ({
    time: new Date(p.timestamp * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    }),
    risk: p.risk_score,
  }));

  return (
    <div className="h-full w-full" style={{ height: 300 }}>
      <ResponsiveContainer>
        <LineChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
          <XAxis
            dataKey="time"
            tick={{ fontSize: 10, fill: '#6b7280' }}
            tickLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fontSize: 10, fill: '#6b7280' }}
            tickLine={false}
            domain={[0, 'auto']}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1f2937',
              border: '1px solid #374151',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#f3f4f6',
            }}
          />
          <Line
            type="monotone"
            dataKey="risk"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, fill: '#3b82f6' }}
          />
          <Brush dataKey="time" height={20} stroke="#3b82f6" fill="#1f2937" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
