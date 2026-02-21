import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { Layers } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const LSPNode = memo(function LSPNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<Layers className="w-4 h-4" />}
      color="text-teal-500"
      bgColor="bg-teal-500/15"
      selected={selected}
    />
  );
});

