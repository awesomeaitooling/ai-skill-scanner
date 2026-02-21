import { memo } from 'react';
import { BaseEdge, type Edge, type EdgeProps, getSmoothStepPath } from '@xyflow/react';
import type { EdgeData, Severity } from '../../../types/plugin.types';

type SecurityEdge = Edge<EdgeData>;

const severityColors: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#475569',
  clean: '#334155',
};

export const SecurityEdge = memo(function SecurityEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
}: EdgeProps<SecurityEdge>) {
  // Use smooth step path for cleaner orthogonal lines
  const [edgePath] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 8,
  });

  const severity = data?.severity || 'clean';
  const strokeColor = severityColors[severity];
  const hasIssues = severity !== 'clean' && severity !== 'low';

  return (
    <>
      {/* Main edge - clean and simple */}
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: strokeColor,
          strokeWidth: hasIssues ? 2 : 1.5,
          opacity: hasIssues ? 0.9 : 0.4,
          transition: 'stroke 0.2s, opacity 0.2s',
        }}
      />
    </>
  );
});

