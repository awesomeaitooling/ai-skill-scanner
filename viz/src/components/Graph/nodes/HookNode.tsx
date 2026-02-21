import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { Webhook } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const HookNode = memo(function HookNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<Webhook className="w-4 h-4" />}
      color="text-amber-500"
      bgColor="bg-amber-500/15"
      selected={selected}
    />
  );
});
