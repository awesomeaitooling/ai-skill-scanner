import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { FileCode } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const ScriptNode = memo(function ScriptNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<FileCode className="w-4 h-4" />}
      color="text-rose-500"
      bgColor="bg-rose-500/15"
      selected={selected}
    />
  );
});

