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
  Filter,
  AlertTriangle,
  ShieldAlert,
  Bug,
} from 'lucide-react';
import type { FilterState, NodeType, Section, ScanSummary } from '../../types/plugin.types';

interface FilterPanelProps {
  filters: FilterState;
  onChange: (filters: FilterState) => void;
  summary?: ScanSummary;
}

const nodeTypeConfig: { type: NodeType; icon: React.ReactNode; label: string; color: string }[] = [
  { type: 'plugin', icon: <Package className="w-3.5 h-3.5" />, label: 'Plugin', color: 'text-slate-400' },
  { type: 'skill', icon: <Zap className="w-3.5 h-3.5" />, label: 'Skills', color: 'text-indigo-500' },
  { type: 'command', icon: <Terminal className="w-3.5 h-3.5" />, label: 'Commands', color: 'text-violet-500' },
  { type: 'hook', icon: <Webhook className="w-3.5 h-3.5" />, label: 'Hooks', color: 'text-amber-500' },
  { type: 'mcp', icon: <Server className="w-3.5 h-3.5" />, label: 'MCP', color: 'text-cyan-500' },
  { type: 'lsp', icon: <Layers className="w-3.5 h-3.5" />, label: 'LSP', color: 'text-teal-500' },
  { type: 'agent', icon: <Bot className="w-3.5 h-3.5" />, label: 'Agents', color: 'text-emerald-500' },
  { type: 'script', icon: <FileCode className="w-3.5 h-3.5" />, label: 'Scripts', color: 'text-rose-500' },
  { type: 'resource', icon: <File className="w-3.5 h-3.5" />, label: 'Resources', color: 'text-slate-400' },
];

export function FilterPanel({ filters, onChange, summary }: FilterPanelProps) {
  const toggleNodeType = (type: NodeType) => {
    onChange({
      ...filters,
      nodeTypes: {
        ...filters.nodeTypes,
        [type]: !filters.nodeTypes[type],
      },
    });
  };

  const toggleShowOnlyVulnerable = () => {
    onChange({
      ...filters,
      showOnlyVulnerable: !filters.showOnlyVulnerable,
    });
  };

  const toggleSection = (section: Section) => {
    onChange({
      ...filters,
      sectionFilter: {
        ...filters.sectionFilter,
        [section]: !filters.sectionFilter[section],
      },
    });
  };

  const selectAll = () => {
    const allEnabled: Record<NodeType, boolean> = {} as Record<NodeType, boolean>;
    nodeTypeConfig.forEach((config) => {
      allEnabled[config.type] = true;
    });
    onChange({
      ...filters,
      nodeTypes: allEnabled,
    });
  };

  const selectNone = () => {
    const allDisabled: Record<NodeType, boolean> = {} as Record<NodeType, boolean>;
    nodeTypeConfig.forEach((config) => {
      allDisabled[config.type] = false;
    });
    // Keep plugin always visible
    allDisabled.plugin = true;
    onChange({
      ...filters,
      nodeTypes: allDisabled,
    });
  };

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-foreground-muted uppercase tracking-wider flex items-center gap-2">
          <Filter className="w-4 h-4" />
          Filters
        </h2>
        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={selectAll}
            className="text-foreground-muted hover:text-foreground-secondary transition-colors"
          >
            All
          </button>
          <span className="text-foreground-muted/50">|</span>
          <button
            onClick={selectNone}
            className="text-foreground-muted hover:text-foreground-secondary transition-colors"
          >
            None
          </button>
        </div>
      </div>

      {/* Security filter */}
      <div className="mb-4">
        <button
          onClick={toggleShowOnlyVulnerable}
          className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors ${
            filters.showOnlyVulnerable
              ? 'bg-amber-500/15 border-amber-500/30 text-amber-500'
              : 'bg-surface/50 border-border text-foreground-secondary hover:text-foreground'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span className="text-sm font-medium">Show only vulnerable</span>
          {filters.showOnlyVulnerable && (
            <div className="ml-auto w-2 h-2 rounded-full bg-amber-500" />
          )}
        </button>
      </div>

      {/* Section filter */}
      <div className="mb-4">
        <div className="text-xs text-foreground-muted mb-2 uppercase tracking-wider font-medium">
          Finding Section
        </div>
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => toggleSection('malicious')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors ${
              filters.sectionFilter.malicious
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-500'
                : 'bg-surface/50 border-border text-foreground-secondary hover:text-foreground opacity-50'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span className="text-xs font-medium">Malicious</span>
          </button>
          <button
            onClick={() => toggleSection('code_security')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors ${
              filters.sectionFilter.code_security
                ? 'bg-sky-500/15 border-sky-500/30 text-sky-500'
                : 'bg-surface/50 border-border text-foreground-secondary hover:text-foreground opacity-50'
            }`}
          >
            <Bug className="w-4 h-4" />
            <span className="text-xs font-medium">Code Security</span>
          </button>
        </div>
      </div>

      {/* Node type filters */}
      <div className="grid grid-cols-3 gap-2">
        {nodeTypeConfig.map((config) => {
          const isEnabled = filters.nodeTypes[config.type];
          const count = summary?.componentTypes[config.type] || 0;

          return (
            <button
              key={config.type}
              onClick={() => toggleNodeType(config.type)}
              disabled={config.type === 'plugin'} // Plugin always visible
              className={`flex flex-col items-center gap-1 p-2 rounded-lg border transition-all ${
                isEnabled
                  ? 'bg-surface/80 border-border-strong'
                  : 'bg-surface/20 border-border opacity-50'
              } ${config.type === 'plugin' ? 'cursor-not-allowed' : 'hover:bg-surface/60'}`}
            >
              <span className={isEnabled ? config.color : 'text-foreground-muted'}>
                {config.icon}
              </span>
              <span className={`text-xs ${isEnabled ? 'text-foreground-secondary' : 'text-foreground-muted'}`}>
                {config.label}
              </span>
              {count > 0 && (
                <span
                  className={`text-xs px-1.5 rounded-full ${
                    isEnabled ? 'bg-surface text-foreground-secondary' : 'bg-surface/50 text-foreground-muted'
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
