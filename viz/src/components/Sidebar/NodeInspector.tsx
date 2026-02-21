import {
  Package,
  Zap,
  Terminal,
  Webhook,
  Server,
  Bot,
  FileCode,
  File,
  MapPin,
  GitBranch,
  Layers,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Bug,
} from 'lucide-react';
import { useState } from 'react';
import type { GraphNode, NodeType, Finding, Severity, Section } from '../../types/plugin.types';
import { SeverityBadge, SectionBadge, CategoryBadge } from '../shared/Badge';

interface NodeInspectorProps {
  node: GraphNode | null;
}

const nodeIcons: Record<NodeType, React.ReactNode> = {
  plugin: <Package className="w-5 h-5" />,
  skill: <Zap className="w-5 h-5" />,
  command: <Terminal className="w-5 h-5" />,
  hook: <Webhook className="w-5 h-5" />,
  mcp: <Server className="w-5 h-5" />,
  lsp: <Layers className="w-5 h-5" />,
  agent: <Bot className="w-5 h-5" />,
  script: <FileCode className="w-5 h-5" />,
  resource: <File className="w-5 h-5" />,
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

export function NodeInspector({ node }: NodeInspectorProps) {
  if (!node) {
    return (
      <div className="p-4">
        <h2 className="text-sm font-semibold text-foreground-muted uppercase tracking-wider mb-3">
          Node Inspector
        </h2>
        <div className="text-sm text-foreground-muted italic">
          Select a node to view details
        </div>
      </div>
    );
  }

  const nodeType = node.type as NodeType;
  const icon = nodeIcons[nodeType];
  const colorClass = nodeColors[nodeType];

  return (
    <div className="p-4">
      <h2 className="text-sm font-semibold text-foreground-muted uppercase tracking-wider mb-3">
        Node Inspector
      </h2>

      {/* Node header */}
      <div className="flex items-start gap-3 mb-4">
        <div className={`p-2 rounded-lg bg-surface ${colorClass}`}>
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-semibold text-foreground truncate">
            {node.data.label}
          </h3>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs font-medium text-foreground-muted uppercase">
              {nodeType}
            </span>
            <SeverityBadge severity={node.data.severity} />
          </div>
        </div>
      </div>

      {/* Node details */}
      <div className="space-y-3">
        {/* Path */}
        {node.data.path && (
          <div className="flex items-start gap-2">
            <MapPin className="w-4 h-4 text-foreground-muted mt-0.5 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-xs text-foreground-muted mb-0.5">Path</div>
              <div className="text-sm font-mono text-foreground-secondary truncate">
                {node.data.path}
              </div>
            </div>
          </div>
        )}

        {/* Version (for plugin nodes) */}
        {node.data.version && (
          <div className="flex items-start gap-2">
            <GitBranch className="w-4 h-4 text-foreground-muted mt-0.5 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-xs text-foreground-muted mb-0.5">Version</div>
              <div className="text-sm font-mono text-foreground-secondary">
                {node.data.version}
              </div>
            </div>
          </div>
        )}

        {/* Description */}
        {node.data.description && (
          <div className="mt-3 p-3 bg-surface/50 rounded-lg">
            <div className="text-xs text-foreground-muted mb-1">Description</div>
            <div className="text-sm text-foreground-secondary">{node.data.description}</div>
          </div>
        )}

        {/* Metadata */}
        {node.data.metadata && Object.keys(node.data.metadata).length > 0 && (
          <div className="mt-3">
            <div className="text-xs text-foreground-muted mb-2">Metadata</div>
            <div className="space-y-1.5">
              {Object.entries(node.data.metadata).map(([key, value]) => (
                <div
                  key={key}
                  className="flex items-start justify-between text-sm py-1 px-2 rounded bg-surface/30"
                >
                  <span className="text-foreground-muted">{key}</span>
                  <span className="text-foreground-secondary font-mono text-xs truncate max-w-[180px]">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Component counts (for plugin nodes) */}
        {node.data.componentCounts && (
          <div className="mt-3">
            <div className="text-xs text-foreground-muted mb-2">Components</div>
            <div className="grid grid-cols-3 gap-2">
              {Object.entries(node.data.componentCounts)
                .filter(([, count]) => count > 0)
                .map(([type, count]) => (
                  <div
                    key={type}
                    className="flex items-center gap-1.5 text-xs p-1.5 rounded bg-surface/50"
                  >
                    <span className={nodeColors[type as NodeType]}>
                      {nodeIcons[type as NodeType]}
                    </span>
                    <span className="text-foreground-secondary">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Findings section */}
        <div className="mt-4 pt-3 border-t border-border">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-foreground-secondary">Security Findings</span>
            <span
              className={`px-2 py-0.5 text-sm font-semibold rounded ${
                node.data.findingsCount > 0
                  ? 'bg-red-500/15 text-red-500'
                  : 'bg-green-500/15 text-green-500'
              }`}
            >
              {node.data.findingsCount}
            </span>
          </div>

          {/* Findings list */}
          {node.data.findings && node.data.findings.length > 0 ? (
            <FindingsList findings={node.data.findings} />
          ) : (
            <div className="text-sm text-green-600 bg-green-500/10 p-3 rounded-lg border border-green-500/20">
              No security issues found
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Severity icons for findings
const severityIcons: Record<Severity, React.ReactNode> = {
  critical: <AlertTriangle className="w-4 h-4" />,
  high: <AlertCircle className="w-4 h-4" />,
  medium: <AlertCircle className="w-4 h-4" />,
  low: <Info className="w-4 h-4" />,
  clean: null,
};

const severityColors: Record<Severity, string> = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/25',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/25',
  medium: 'text-yellow-600 bg-yellow-500/10 border-yellow-500/25',
  low: 'text-foreground-muted bg-surface/50 border-border',
  clean: 'text-green-500 bg-green-500/10 border-green-500/25',
};

interface FindingsListProps {
  findings: Finding[];
}

// Section display config
const sectionDisplayConfig: Record<Section, { label: string; icon: React.ReactNode; color: string }> = {
  malicious: {
    label: 'Malicious Check',
    icon: <ShieldAlert className="w-4 h-4" />,
    color: 'text-rose-500',
  },
  code_security: {
    label: 'Code Security Issues',
    icon: <Bug className="w-4 h-4" />,
    color: 'text-sky-500',
  },
};

const SECTION_ORDER: Section[] = ['malicious', 'code_security'];

function FindingsList({ findings }: FindingsListProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Sort by severity within each group
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low'];
  const sortedFindings = [...findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  // Group by section
  const grouped: Record<Section, Finding[]> = { malicious: [], code_security: [] };
  for (const f of sortedFindings) {
    const section: Section = f.section || 'code_security';
    grouped[section].push(f);
  }

  return (
    <div className="space-y-4">
      {SECTION_ORDER.map((section) => {
        const group = grouped[section];
        if (group.length === 0) return null;
        const config = sectionDisplayConfig[section];

        return (
          <div key={section}>
            {/* Section group header */}
            <div className={`flex items-center gap-2 mb-2 ${config.color}`}>
              {config.icon}
              <span className="text-xs font-semibold uppercase tracking-wider">
                {config.label}
              </span>
              <span className="text-xs opacity-70">({group.length})</span>
            </div>

            <div className="space-y-2">
              {group.map((finding, index) => {
                const uniqueId = `${section}-${finding.ruleId}-${index}`;
                const isExpanded = expandedIds.has(uniqueId);
                const colorClass = severityColors[finding.severity];

                return (
                  <div
                    key={uniqueId}
                    className={`rounded-lg border ${colorClass}`}
                  >
                    <button
                      onClick={() => toggleExpanded(uniqueId)}
                      className="w-full flex items-start gap-2 p-2.5 text-left hover:bg-surface/30 transition-colors rounded-lg"
                    >
                      <span className="mt-0.5 flex-shrink-0">
                        {severityIcons[finding.severity]}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium truncate">
                            {finding.ruleName}
                          </span>
                          <SeverityBadge severity={finding.severity} size="sm" />
                        </div>
                        {!isExpanded && (
                          <p className="text-xs opacity-70 mt-0.5 line-clamp-1">
                            {finding.message}
                          </p>
                        )}
                      </div>
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 opacity-50 flex-shrink-0" />
                      ) : (
                        <ChevronRight className="w-4 h-4 opacity-50 flex-shrink-0" />
                      )}
                    </button>

                    {isExpanded && (
                      <div className="px-2.5 pb-2.5 pt-0 space-y-2">
                        {/* Rule ID and badges */}
                        <div className="flex items-center gap-2 text-xs flex-wrap">
                          <span className="opacity-60">Rule:</span>
                          <code className="px-1.5 py-0.5 bg-surface rounded font-mono text-foreground-secondary">
                            {finding.ruleId}
                          </code>
                          {finding.section && (
                            <SectionBadge section={finding.section} size="sm" />
                          )}
                          {finding.category && (
                            <CategoryBadge category={finding.category} />
                          )}
                        </div>

                        {/* File path */}
                        {finding.filePath && (
                          <div className="flex items-center gap-2 text-xs">
                            <span className="opacity-60">File:</span>
                            <code className="font-mono text-foreground-secondary truncate">{finding.filePath}</code>
                          </div>
                        )}

                        {/* Line number */}
                        {finding.line && (
                          <div className="flex items-center gap-2 text-xs">
                            <span className="opacity-60">Line:</span>
                            <span className="font-mono">{finding.line}</span>
                          </div>
                        )}

                        {/* Code snippet */}
                        {finding.snippet && (
                          <div className="rounded border border-border/60 overflow-hidden">
                            <div className="bg-[#1e1e2e] px-3 py-2 overflow-x-auto">
                              <pre className="text-xs font-mono text-[#cdd6f4] whitespace-pre leading-relaxed">
                                {finding.line ? (
                                  finding.snippet.split('\n').map((snippetLine, i) => (
                                    <div key={i} className="flex">
                                      <span className="select-none text-[#585b70] mr-3 text-right inline-block" style={{ minWidth: '2.5ch' }}>
                                        {finding.line! + i}
                                      </span>
                                      <span>{snippetLine}</span>
                                    </div>
                                  ))
                                ) : (
                                  <code>{finding.snippet}</code>
                                )}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Message */}
                        <div className="p-2 bg-surface/50 rounded text-xs text-foreground-secondary">
                          {finding.message}
                        </div>

                        {/* Recommendation */}
                        {finding.recommendation && (
                          <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded">
                            <div className="text-xs text-emerald-600 font-medium mb-1">
                              Recommendation
                            </div>
                            <div className="text-xs text-foreground-secondary">
                              {finding.recommendation}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
