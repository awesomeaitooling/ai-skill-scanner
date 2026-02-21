import { memo } from 'react';
import { type Node, type NodeProps, Handle, Position } from '@xyflow/react';
import { Package, ShieldAlert, ShieldCheck, Bug } from 'lucide-react';
import type { NodeData, Severity } from '../../../types/plugin.types';

const severityStyles: Record<Severity, { accent: string; badge: string }> = {
  critical: { accent: 'from-red-500', badge: 'bg-red-500/15 text-red-500' },
  high: { accent: 'from-orange-500', badge: 'bg-orange-500/15 text-orange-500' },
  medium: { accent: 'from-yellow-500', badge: 'bg-yellow-600/15 text-yellow-600' },
  low: { accent: 'from-slate-400', badge: 'bg-slate-500/15 text-slate-500' },
  clean: { accent: 'from-emerald-500', badge: 'bg-emerald-500/15 text-emerald-600' },
};

export const PluginNode = memo(function PluginNode({
  data,
  selected,
}: NodeProps<Node<NodeData>>) {
  const severity = data.severity || 'clean';
  const styles = severityStyles[severity];
  const totalFindings = data.totalFindings ?? data.findingsCount;
  const totalMalicious = data.totalMalicious ?? 0;
  const totalCodeSecurity = data.totalCodeSecurity ?? 0;

  return (
    <>
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-accent-cyan !border-0 !rounded-full opacity-0"
      />

      <div
        className={`
          w-[220px] rounded-xl overflow-hidden
          bg-background-card border border-border-strong
          shadow-xl shadow-black/15
          transition-all duration-150
          ${selected ? 'ring-2 ring-accent-cyan/60 scale-105' : 'hover:border-accent-cyan/30'}
        `}
      >
        {/* Accent bar */}
        <div className={`h-1 bg-gradient-to-r ${styles.accent} to-transparent`} />

        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-3">
          <div className="p-2 rounded-lg bg-accent-cyan/15 text-accent-cyan">
            <Package className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-bold text-foreground truncate">
              {data.label}
            </div>
            {data.version && (
              <div className="text-xs text-foreground-secondary font-mono">
                v{data.version}
              </div>
            )}
          </div>
        </div>

        {/* Safety verdict banner */}
        <div className={`mx-3 mb-2 flex items-center justify-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider ${
          totalMalicious > 0
            ? 'bg-red-500/10 text-red-500 border border-red-500/20'
            : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
        }`}>
          {totalMalicious > 0
            ? <><ShieldAlert className="w-3 h-3" /> Unsafe</>
            : <><ShieldCheck className="w-3 h-3" /> Safe</>
          }
        </div>

        {/* Component counts - compact grid */}
        {data.componentCounts && (
          <div className="px-4 pb-3">
            <div className="grid grid-cols-4 gap-1">
              {Object.entries(data.componentCounts)
                .filter(([type, count]) => count > 0 && type !== 'plugin')
                .slice(0, 8)
                .map(([type, count]) => (
                  <div
                    key={type}
                    className="text-center py-1 px-1 rounded bg-surface/50"
                  >
                    <div className="text-xs font-semibold text-foreground">{count}</div>
                    <div className="text-[8px] text-foreground-muted uppercase truncate">{type}</div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Footer — aggregate malicious / code-security breakdown */}
        <div className="px-4 py-2 bg-surface/30 border-t border-border/50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {totalMalicious > 0 && (
                <span className="inline-flex items-center gap-1 text-rose-500">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span className="text-xs font-semibold">{totalMalicious}</span>
                </span>
              )}
              {totalCodeSecurity > 0 && (
                <span className="inline-flex items-center gap-1 text-sky-500">
                  <Bug className="w-3.5 h-3.5" />
                  <span className="text-xs font-semibold">{totalCodeSecurity}</span>
                </span>
              )}
              {totalFindings === 0 && (
                <span className="text-xs text-emerald-500 font-medium">Clean</span>
              )}
            </div>
            <span className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded ${styles.badge}`}>
              {totalFindings} issue{totalFindings !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-foreground-muted !border-0 !rounded-full opacity-60"
      />
    </>
  );
});
