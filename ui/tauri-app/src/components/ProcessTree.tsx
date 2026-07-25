import { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  Position,
} from 'reactflow';
import 'reactflow/dist/style.css';

interface ProcessNode {
  id: string;
  pid: number;
  ppid: number;
  name: string;
  cpu: number;
  memory_mb: number;
  risk: number;
}

export default function ProcessTree({ data }: { data: { nodes: ProcessNode[] } }) {
  const { nodes, edges } = useMemo(() => {
    if (!data?.nodes?.length) return { nodes: [], edges: [] };

    const nodeMap = new Map<number, ProcessNode>();
    for (const p of data.nodes) nodeMap.set(p.pid, p);

    const layoutNodes: Node[] = data.nodes.map((p, i) => ({
      id: String(p.pid),
      position: { x: (i % 8) * 220, y: Math.floor(i / 8) * 100 },
      data: {
        label: (
          <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg px-3 py-1.5 shadow-sm text-xs">
            <div className="font-mono font-bold text-gray-900 dark:text-white text-[11px] truncate max-w-[180px]">{p.name}</div>
            <div className="flex items-center gap-2 mt-0.5 text-[10px] text-gray-500">
              <span>PID {p.pid}</span>
              <span>{p.cpu.toFixed(1)}%</span>
              <span>{Math.round(p.memory_mb)}MB</span>
            </div>
            {p.risk > 0 && (
              <div className="mt-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded px-1 text-[9px] inline-block">
                Risk {p.risk}
              </div>
            )}
          </div>
        ),
      },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
      style: p.risk > 50
        ? { border: '2px solid #ef4444', borderRadius: '8px' }
        : p.risk > 20
        ? { border: '2px solid #f59e0b', borderRadius: '8px' }
        : undefined,
    }));

    const layoutEdges: Edge[] = [];
    for (const p of data.nodes) {
      if (p.ppid > 0 && nodeMap.has(p.ppid)) {
        layoutEdges.push({
          id: `${p.ppid}-${p.pid}`,
          source: String(p.ppid),
          target: String(p.pid),
          type: 'smoothstep',
          animated: false,
          style: { stroke: '#94a3b8' },
        });
      }
    }

    return { nodes: layoutNodes, edges: layoutEdges };
  }, [data]);

  if (!nodes.length) {
    return (
      <div className="flex h-full items-center justify-center text-gray-400">
        <p>No process data available</p>
      </div>
    );
  }

  return (
    <div className="h-full w-full" style={{ height: 400 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#e2e8f0" gap={20} />
        <Controls />
        <MiniMap
          nodeColor={(n) => {
            const d = n.data?.label?.props?.children?.[2]?.props?.children;
            return d ? '#3b82f6' : '#94a3b8';
          }}
          style={{ backgroundColor: 'transparent' }}
        />
      </ReactFlow>
    </div>
  );
}
