import { useQuery } from '@tanstack/react-query';
import { Network as NetworkIcon } from 'lucide-react';
import * as api from '../utils/tauriApi';
import NetworkMap from '../components/NetworkMap';

export default function Network() {
  const graph = useQuery({
    queryKey: ['network-graph-full'],
    queryFn: api.getNetworkGraph,
    refetchInterval: 30000,
  });

  const totalNodes = graph.data?.nodes?.length ?? 0;
  const totalEdges = graph.data?.edges?.length ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Network</h1>
          <p className="text-gray-500 dark:text-gray-400">
            {graph.isLoading ? 'Loading...' : `${totalNodes} hosts, ${totalEdges} connections`}
          </p>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="border-b border-gray-200 px-6 py-4 dark:border-gray-700 flex items-center gap-2">
          <NetworkIcon className="h-5 w-5 text-blue-500" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Connection Graph</h2>
        </div>
        <NetworkMap data={graph.data ?? { nodes: [], edges: [] }} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-blue-600">{totalNodes}</p>
          <p className="text-sm text-gray-500">Hosts</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-green-600">{totalEdges}</p>
          <p className="text-sm text-gray-500">Connections</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-purple-600">{totalNodes > 0 ? Math.round((totalEdges / totalNodes) * 10) / 10 : 0}</p>
          <p className="text-sm text-gray-500">Avg degree</p>
        </div>
      </div>
    </div>
  );
}
