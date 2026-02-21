import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { File } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const ResourceNode = memo(function ResourceNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<File className="w-4 h-4" />}
      color="text-slate-500"
      bgColor="bg-slate-500/15"
      selected={selected}
    />
  );
});

