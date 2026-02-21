import { memo } from 'react';
import { type Node, type NodeProps } from '@xyflow/react';
import { Zap } from 'lucide-react';
import { BaseNode } from './BaseNode';
import type { NodeData } from '../../../types/plugin.types';

export const SkillNode = memo(function SkillNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  return (
    <BaseNode
      data={data}
      icon={<Zap className="w-4 h-4" />}
      color="text-indigo-500"
      bgColor="bg-indigo-500/15"
      selected={selected}
    />
  );
});

