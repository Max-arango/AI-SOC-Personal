import { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';

interface GraphNode {
  id: number;
  label: string;
  risk: number;
}

interface GraphEdge {
  from: number;
  to: number;
  protocol: string;
  local_port: number;
  remote_port: number;
}

export default function NetworkMap({
  data,
}: {
  data: { nodes: GraphNode[]; edges: GraphEdge[] };
}) {
  const { nodes, edges } = useMemo(() => {
    if (!data?.nodes?.length) return { nodes: [], edges: [] };

    const layoutNodes: Node[] = data.nodes.map((n, i) => ({
      id: String(n.id),
      position: { x: (i % 6) * 200, y: Math.floor(i / 6) * 150 },
      data: {
        label: (
          <div
            className={`rounded-full px-3 py-2 text-xs font-mono shadow-sm ${
              n.risk > 50
                ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-300'
                : n.risk > 0
                ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 border border-yellow-300'
                : 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border border-blue-300'
            }`}
          >
            {n.label}
          </div>
        ),
      },
      style: { border: 'none', background: 'transparent' },
    }));

    const layoutEdges: Edge[] = data.edges.map((e, i) => ({
      id: `${e.from}-${e.to}-${i}`,
      source: String(e.from),
      target: String(e.to),
      label: `${e.remote_port}/${e.protocol}`,
      animated: true,
      markerEnd: { type: MarkerType.ArrowClosed, color: '#94a3b8' },
      style: { stroke: '#94a3b8', strokeWidth: 1 },
      labelStyle: { fontSize: 9, fill: '#94a3b8' },
    }));

    return { nodes: layoutNodes, edges: layoutEdges };
  }, [data]);

  if (!nodes.length) {
    return (
      <div className="flex h-full items-center justify-center text-gray-400">
        <p>No network connections recorded</p>
      </div>
    );
  }

  return (
    <div className="h-full w-full" style={{ height: 400 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#e2e8f0" gap={20} />
        <Controls />
      </ReactFlow>
    </div>
  );
}
