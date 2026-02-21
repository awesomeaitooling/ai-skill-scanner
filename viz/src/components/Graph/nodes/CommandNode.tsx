import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { Terminal } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const CommandNode = memo(function CommandNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<Terminal className="w-4 h-4" />}
      color="text-violet-500"
      bgColor="bg-violet-500/15"
      selected={selected}
    />
  );
});

