import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { Server } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const MCPNode = memo(function MCPNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<Server className="w-4 h-4" />}
      color="text-cyan-500"
      bgColor="bg-cyan-500/15"
      selected={selected}
    />
  );
});

