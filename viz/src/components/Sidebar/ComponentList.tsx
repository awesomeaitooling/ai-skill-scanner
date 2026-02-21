import { useState } from 'react';
import {
  Package,
  Zap,
  Terminal,
  Webhook,
  Server,
  Bot,
  FileCode,
  File,
  Layers,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Bug,
} from 'lucide-react';
import type { GraphNode, NodeType, Severity } from '../../types/plugin.types';
import { SeverityBadge } from '../shared/Badge';

interface ComponentListProps {
  nodes: GraphNode[];
  selectedNodeId?: string;
  onSelectNode: (nodeId: string) => void;
}

const nodeIcons: Record<NodeType, React.ReactNode> = {
  plugin: <Package className="w-4 h-4" />,
  skill: <Zap className="w-4 h-4" />,
  command: <Terminal className="w-4 h-4" />,
  hook: <Webhook className="w-4 h-4" />,
  mcp: <Server className="w-4 h-4" />,
  lsp: <Layers className="w-4 h-4" />,
  agent: <Bot className="w-4 h-4" />,
  script: <FileCode className="w-4 h-4" />,
  resource: <File className="w-4 h-4" />,
};

const nodeColors: Record<NodeType, string> = {
  plugin: 'text-slate-400',
  skill: 'text-indigo-500',
  command: 'text-violet-500',
  hook: 'text-amber-500',
  mcp: 'text-cyan-500',
  lsp: 'text-teal-500',
  agent: 'text-emerald-500',
  script: 'text-rose-500',
  resource: 'text-slate-400',
};

const groupLabels: Partial<Record<NodeType, string>> = {
  plugin: 'Plugin',
  skill: 'Skills',
  command: 'Commands',
  hook: 'Hooks',
  mcp: 'MCP Servers',
  lsp: 'LSP Servers',
  agent: 'Agents',
  script: 'Scripts',
  resource: 'Resources',
};

const GROUP_ORDER: NodeType[] = [
  'plugin',
  'skill',
  'command',
  'agent',
  'hook',
  'mcp',
  'lsp',
  'script',
  'resource',
];

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'clean'];

export function ComponentList({ nodes, selectedNodeId, onSelectNode }: ComponentListProps) {
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  if (nodes.length === 0) {
    return (
      <div className="p-4">
        <h2 className="text-sm font-semibold text-foreground-muted uppercase tracking-wider mb-3">
          Components
        </h2>
        <div className="text-sm text-foreground-muted italic">No scan loaded</div>
      </div>
    );
  }

  const grouped: Partial<Record<NodeType, GraphNode[]>> = {};
  for (const node of nodes) {
    const type = node.type as NodeType;
    if (!grouped[type]) grouped[type] = [];
    grouped[type]!.push(node);
  }

  // Sort nodes within each group by severity (worst first), then name
  for (const group of Object.values(grouped)) {
    group?.sort((a, b) => {
      const si = severityOrder.indexOf(a.data.severity) - severityOrder.indexOf(b.data.severity);
      if (si !== 0) return si;
      return a.data.label.localeCompare(b.data.label);
    });
  }

  const toggleGroup = (type: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  // Aggregate stats for the summary bar
  const totalComponents = nodes.filter((n) => n.type !== 'plugin').length;
  const vulnerableCount = nodes.filter(
    (n) => n.type !== 'plugin' && n.data.findingsCount > 0,
  ).length;

  return (
    <div className="p-4">
      <h2 className="text-sm font-semibold text-foreground-muted uppercase tracking-wider mb-3">
        Components
      </h2>

      {/* Quick summary */}
      <div className="flex items-center gap-3 mb-4 px-3 py-2 bg-surface/50 rounded-lg border border-border/50">
        <span className="text-xs text-foreground-secondary">
          <span className="font-semibold text-foreground">{totalComponents}</span> components
        </span>
        {vulnerableCount > 0 && (
          <>
            <div className="h-3 w-px bg-border" />
            <span className="text-xs text-amber-500 font-medium">
              {vulnerableCount} with issues
            </span>
          </>
        )}
      </div>

      {/* Grouped list */}
      <div className="space-y-1">
        {GROUP_ORDER.map((type) => {
          const group = grouped[type];
          if (!group || group.length === 0) return null;

          const isCollapsed = collapsedGroups.has(type);
          const label = groupLabels[type] || type;
          const groupFindings = group.reduce((sum, n) => sum + n.data.findingsCount, 0);

          return (
            <div key={type}>
              {/* Group header */}
              <button
                onClick={() => toggleGroup(type)}
                className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-surface/50 transition-colors"
              >
                {isCollapsed ? (
                  <ChevronRight className="w-3.5 h-3.5 text-foreground-muted" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-foreground-muted" />
                )}
                <span className={nodeColors[type]}>{nodeIcons[type]}</span>
                <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider flex-1 text-left">
                  {label}
                </span>
                <span className="text-[10px] text-foreground-muted">{group.length}</span>
                {groupFindings > 0 && (
                  <span className="text-[10px] font-medium text-amber-500 bg-amber-500/10 px-1.5 rounded">
                    {groupFindings}
                  </span>
                )}
              </button>

              {/* Group items */}
              {!isCollapsed && (
                <div className="ml-2 space-y-0.5">
                  {group.map((node) => (
                    <ComponentRow
                      key={node.id}
                      node={node}
                      isSelected={node.id === selectedNodeId}
                      onClick={() => onSelectNode(node.id)}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface ComponentRowProps {
  node: GraphNode;
  isSelected: boolean;
  onClick: () => void;
}

function ComponentRow({ node, isSelected, onClick }: ComponentRowProps) {
  const hasMalicious = node.data.findings.some((f) => f.section === 'malicious');
  const hasCodeSecurity = node.data.findings.some(
    (f) => (f.section || 'code_security') === 'code_security',
  );

  return (
    <button
      onClick={onClick}
      className={`
        w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left transition-all
        ${
          isSelected
            ? 'bg-accent-cyan/10 border border-accent-cyan/30'
            : 'hover:bg-surface/60 border border-transparent'
        }
      `}
    >
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium text-foreground truncate">{node.data.label}</div>
        {node.data.path && (
          <div className="text-[10px] text-foreground-muted font-mono truncate mt-0.5">
            {node.data.path}
          </div>
        )}
      </div>

      {/* Section mini-icons */}
      <div className="flex items-center gap-1 flex-shrink-0">
        {hasMalicious && <ShieldAlert className="w-3 h-3 text-rose-500" />}
        {hasCodeSecurity && node.data.findingsCount > 0 && (
          <Bug className="w-3 h-3 text-sky-500" />
        )}
      </div>

      {/* Severity + count */}
      {node.data.findingsCount > 0 ? (
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <span className="text-[10px] font-medium text-foreground-muted">
            {node.data.findingsCount}
          </span>
          <SeverityBadge severity={node.data.severity} size="sm" />
        </div>
      ) : (
        <SeverityBadge severity="clean" size="sm" />
      )}
    </button>
  );
}
