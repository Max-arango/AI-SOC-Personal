import { useQuery } from '@tanstack/react-query';
import { Network as NetworkIcon } from 'lucide-react';
import * as api from '../utils/tauriApi';

export default function Network() {
  const connections = useQuery({
    queryKey: ['network'],
    queryFn: () => api.getNetworkConnections({ limit: 200 }),
    refetchInterval: 10000,
  });

  const items = connections.data?.connections ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Network</h1>
        <p className="text-gray-500 dark:text-gray-400">
          {connections.isLoading ? 'Loading...' : `${items.length} active connections`}
        </p>
      </div>
      <div className="card">
        <div className="p-12 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/30">
            <NetworkIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">Network Monitoring</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Network collector coming in a future update. Real-time connection monitoring will appear here.
          </p>
        </div>
      </div>
    </div>
  );
}
