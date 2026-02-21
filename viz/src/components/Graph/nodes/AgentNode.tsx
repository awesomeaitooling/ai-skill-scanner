import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { Bot } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const AgentNode = memo(function AgentNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<Bot className="w-4 h-4" />}
      color="text-emerald-500"
      bgColor="bg-emerald-500/15"
      selected={selected}
    />
  );
});

