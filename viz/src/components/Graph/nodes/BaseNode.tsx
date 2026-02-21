import { Handle, Position } from '@xyflow/react';
import { ShieldAlert, Bug } from 'lucide-react';
import type { NodeData, Severity } from '../../../types/plugin.types';

interface BaseNodeProps {
  data: NodeData;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  selected?: boolean;
}

const severityStyles: Record<Severity, { border: string; indicator: string; badge: string }> = {
  critical: {
    border: 'border-l-red-500 border-l-4',
    indicator: 'bg-red-500',
    badge: 'bg-red-500/15 text-red-500',
  },
  high: {
    border: 'border-l-orange-500 border-l-4',
    indicator: 'bg-orange-500',
    badge: 'bg-orange-500/15 text-orange-500',
  },
  medium: {
    border: 'border-l-yellow-500 border-l-4',
    indicator: 'bg-yellow-500',
    badge: 'bg-yellow-600/15 text-yellow-600',
  },
  low: {
    border: 'border-l-slate-400 border-l-4',
    indicator: 'bg-slate-400',
    badge: 'bg-slate-500/15 text-slate-500',
  },
  clean: {
    border: 'border-l-emerald-500 border-l-4',
    indicator: 'bg-emerald-500',
    badge: 'bg-emerald-500/15 text-emerald-600',
  },
};

export function BaseNode({ data, icon, color, bgColor, selected }: BaseNodeProps) {
  const severity = data.severity || 'clean';
  const styles = severityStyles[severity];

  return (
    <>
      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-foreground-muted !border-0 !rounded-full opacity-60 hover:opacity-100 transition-opacity"
      />

      {/* Node body */}
      <div
        className={`
          relative w-[160px] rounded-lg overflow-hidden
          bg-background-card border border-border
          shadow-lg shadow-black/10
          transition-all duration-150
          ${styles.border}
          ${selected ? 'ring-2 ring-accent-cyan/50 scale-105' : 'hover:border-border-strong'}
        `}
      >
        {/* Compact header */}
        <div className="flex items-center gap-2 px-3 py-2.5">
          <div className={`p-1.5 rounded-md ${bgColor} ${color}`}>
            {icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-semibold text-foreground truncate leading-tight">
              {data.label}
            </div>
            <div className="text-[10px] text-foreground-muted uppercase tracking-wide mt-0.5">
              {data.componentType || 'component'}
            </div>
          </div>
        </div>

        {/* Simple footer */}
        {data.findingsCount > 0 && (
          <div className="px-3 py-1.5 bg-surface/30 border-t border-border/50">
            <div className="flex items-center gap-1.5">
              <div className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium ${styles.badge}`}>
                <div className={`w-1.5 h-1.5 rounded-full ${styles.indicator}`} />
                {data.findingsCount} issue{data.findingsCount !== 1 ? 's' : ''}
              </div>
              <SectionIcons findings={data.findings} />
            </div>
          </div>
        )}
      </div>

      {/* Output handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-foreground-muted !border-0 !rounded-full opacity-60 hover:opacity-100 transition-opacity"
      />
    </>
  );
}

/** Compact section icons shown in node footer */
function SectionIcons({ findings }: { findings: NodeData['findings'] }) {
  const hasMalicious = findings.some((f) => f.section === 'malicious');
  const hasCodeSecurity = findings.some((f) => (f.section || 'code_security') === 'code_security');

  if (!hasMalicious && !hasCodeSecurity) return null;

  return (
    <div className="flex items-center gap-0.5 ml-auto">
      {hasMalicious && (
        <ShieldAlert className="w-3 h-3 text-rose-500" />
      )}
      {hasCodeSecurity && (
        <Bug className="w-3 h-3 text-sky-500" />
      )}
    </div>
  );
}
