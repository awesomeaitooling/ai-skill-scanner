import { useState, useEffect } from 'react';
import { List, Search } from 'lucide-react';
import { NodeInspector } from './NodeInspector';
import { ComponentList } from './ComponentList';
import type { GraphNode } from '../../types/plugin.types';

type SidebarTab = 'components' | 'inspector';

interface SidebarProps {
  selectedNode: GraphNode | null;
  allNodes: GraphNode[];
  onSelectNode: (nodeId: string) => void;
  isOpen: boolean;
}

export function Sidebar({
  selectedNode,
  allNodes,
  onSelectNode,
  isOpen,
}: SidebarProps) {
  const [activeTab, setActiveTab] = useState<SidebarTab>('components');

  useEffect(() => {
    if (selectedNode) setActiveTab('inspector');
  }, [selectedNode]);

  return (
    <aside
      className={`
        flex flex-col border-l border-border bg-background-elevated/50 backdrop-blur-sm h-full
        transition-all duration-300 ease-in-out overflow-hidden
        ${isOpen ? 'w-[28rem]' : 'w-0 border-l-0'}
      `}
    >
      {/* Tab bar */}
      <div className="flex border-b border-border min-w-[28rem]">
        <button
          onClick={() => setActiveTab('components')}
          className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors ${
            activeTab === 'components'
              ? 'text-accent-cyan border-b-2 border-accent-cyan bg-accent-cyan/5'
              : 'text-foreground-muted hover:text-foreground-secondary'
          }`}
        >
          <List className="w-3.5 h-3.5" />
          Components
        </button>
        <button
          onClick={() => setActiveTab('inspector')}
          className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors ${
            activeTab === 'inspector'
              ? 'text-accent-cyan border-b-2 border-accent-cyan bg-accent-cyan/5'
              : 'text-foreground-muted hover:text-foreground-secondary'
          }`}
        >
          <Search className="w-3.5 h-3.5" />
          Inspector
        </button>
      </div>

      {/* Scrollable content area */}
      <div className="flex-1 overflow-y-auto min-w-[28rem]">
        {activeTab === 'components' ? (
          <ComponentList
            nodes={allNodes}
            selectedNodeId={selectedNode?.id}
            onSelectNode={onSelectNode}
          />
        ) : (
          <NodeInspector node={selectedNode} />
        )}
      </div>
    </aside>
  );
}
