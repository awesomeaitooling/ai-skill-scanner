import { useState, useCallback, useRef, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type OnSelectionChangeParams,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { Header } from './components/Header/Header';
import { Sidebar } from './components/Sidebar/Sidebar';
import { LeftPanel } from './components/LeftPanel/LeftPanel';
import { nodeTypes } from './components/Graph/nodes';
import { edgeTypes } from './components/Graph/edges';
import { usePluginData } from './hooks/usePluginData';
import { useTheme } from './hooks/useTheme';
import type { GraphNode, GraphEdge, NodeData, EdgeData, FilterState, NodeType, Finding, Severity } from './types/plugin.types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'clean'];

const initialFilters: FilterState = {
  nodeTypes: {
    plugin: true,
    skill: true,
    command: true,
    hook: true,
    mcp: true,
    lsp: true,
    agent: true,
    script: true,
    resource: true,
  },
  showOnlyVulnerable: false,
  minSeverity: null,
  sectionFilter: {
    malicious: true,
    code_security: true,
  },
};

function getHighestSeverity(findings: Finding[]): Severity {
  for (const s of SEVERITY_ORDER) {
    if (findings.some((f) => f.severity === s)) return s;
  }
  return 'clean';
}

function filterNodeBySection(data: NodeData, sectionFilter: FilterState['sectionFilter']): NodeData {
  if (sectionFilter.malicious && sectionFilter.code_security) return data;

  const filteredFindings: Finding[] = data.findings.filter((f) => {
    const section = f.section || 'code_security';
    return sectionFilter[section];
  });

  return {
    ...data,
    findings: filteredFindings,
    findingsCount: filteredFindings.length,
    severity: getHighestSeverity(filteredFindings),
  };
}

function applyAllFilters(
  sourceNodes: GraphNode[],
  sourceEdges: GraphEdge[],
  filters: FilterState,
) {
  const sectionFiltered = sourceNodes.map((node) => ({
    ...node,
    data: filterNodeBySection(node.data, filters.sectionFilter),
  }));

  let totalFiltered = 0;
  let maliciousFiltered = 0;
  let codeSecurityFiltered = 0;
  const allFindings: Finding[] = [];

  for (const node of sectionFiltered) {
    totalFiltered += node.data.findingsCount;
    for (const f of node.data.findings) {
      allFindings.push(f);
      const section = f.section || 'code_security';
      if (section === 'malicious') maliciousFiltered++;
      else codeSecurityFiltered++;
    }
  }

  const rootSeverity = getHighestSeverity(allFindings);

  const withAggregates = sectionFiltered.map((node) => {
    if (node.id === 'plugin-root') {
      return {
        ...node,
        data: {
          ...node.data,
          severity: rootSeverity,
          totalFindings: totalFiltered,
          totalMalicious: maliciousFiltered,
          totalCodeSecurity: codeSecurityFiltered,
        },
      };
    }
    return node;
  });

  const filteredNodes = withAggregates.filter((node) => {
    if (!filters.nodeTypes[node.type as NodeType]) return false;
    if (filters.showOnlyVulnerable && node.data.findingsCount === 0) return false;
    if (filters.minSeverity) {
      const nodeIdx = SEVERITY_ORDER.indexOf(node.data.severity);
      const filterIdx = SEVERITY_ORDER.indexOf(filters.minSeverity);
      if (nodeIdx > filterIdx) return false;
    }
    return true;
  });

  const filteredNodeIds = new Set(filteredNodes.map((n) => n.id));
  const filteredEdges = sourceEdges.filter(
    (edge) => filteredNodeIds.has(edge.source) && filteredNodeIds.has(edge.target),
  );

  return { nodes: filteredNodes, edges: filteredEdges };
}

function App() {
  const { theme, toggleTheme } = useTheme();
  const {
    data, isLoading, error, loadFromFile, loadSampleData,
    isMultiScan, multiData, activeScanIndex, setActiveScan, scanList,
  } = usePluginData();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<EdgeData>>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filters, setFilters] = useState<FilterState>(initialFilters);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [leftPanelOpen, setLeftPanelOpen] = useState(true);
  const [leftPanelWidth, setLeftPanelWidth] = useState(260);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const runFilters = useCallback(
    (activeFilters: FilterState) => {
      if (!data) return;
      const { nodes: fn, edges: fe } = applyAllFilters(data.nodes, data.edges, activeFilters);
      setNodes(fn);
      setEdges(fe);
    },
    [data, setNodes, setEdges],
  );

  // Re-apply filters whenever `data` changes (includes scan switching)
  useEffect(() => {
    if (data) {
      runFilters(filters);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const handleFilterChange = useCallback(
    (newFilters: FilterState) => {
      setFilters(newFilters);
      runFilters(newFilters);
    },
    [runFilters],
  );

  const onSelectionChange = useCallback(
    ({ nodes: selectedNodes }: OnSelectionChangeParams) => {
      if (selectedNodes.length > 0) {
        const node = selectedNodes[0] as unknown as GraphNode;
        setSelectedNode(node);
      } else {
        setSelectedNode(null);
      }
    },
    []
  );

  const handleSelectNode = useCallback(
    (nodeId: string) => {
      setNodes((prev) =>
        prev.map((n) => ({ ...n, selected: n.id === nodeId })),
      );
      const found = nodes.find((n) => n.id === nodeId);
      if (found) {
        setSelectedNode(found as unknown as GraphNode);
      }
    },
    [nodes, setNodes],
  );

  const handleScanChange = useCallback(
    (index: number) => {
      setActiveScan(index);
      setSelectedNode(null);
      setFilters(initialFilters);
    },
    [setActiveScan],
  );

  const handleFileUpload = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
      const file = event.target.files?.[0];
      if (file) {
        if (file.size > MAX_FILE_SIZE) {
          console.error(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB, max 50 MB)`);
          return;
        }
        try {
          const text = await file.text();
          const jsonData = JSON.parse(text);
          loadFromFile(jsonData);
          setSelectedNode(null);
          setFilters(initialFilters);
        } catch {
          console.error('Failed to parse JSON file');
        }
      }
      if (event.target) {
        event.target.value = '';
      }
    },
    [loadFromFile]
  );

  const handleLoadClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleLoadSample = useCallback(() => {
    loadSampleData();
    setSelectedNode(null);
    setFilters(initialFilters);
  }, [loadSampleData]);

  return (
    <div className="h-screen w-screen flex flex-col bg-background">
      <input
        ref={fileInputRef}
        type="file"
        accept=".json"
        onChange={handleFileUpload}
        className="hidden"
      />

      <Header
        pluginName={data?.plugin.name}
        pluginVersion={data?.plugin.version}
        scanType={data?.scanType}
        verdict={data?.verdict}
        summary={data?.summary}
        onLoadClick={handleLoadClick}
        onLoadSample={handleLoadSample}
        theme={theme}
        onToggleTheme={toggleTheme}
        leftPanelOpen={leftPanelOpen}
        onToggleLeftPanel={() => setLeftPanelOpen((v) => !v)}
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen((v) => !v)}
        isMultiScan={isMultiScan}
        scanList={scanList}
        activeScanIndex={activeScanIndex}
        onScanChange={handleScanChange}
        aggregate={multiData?.aggregate}
      />

      <div className="flex-1 flex overflow-hidden">
        <LeftPanel
          isOpen={leftPanelOpen}
          width={leftPanelWidth}
          onWidthChange={setLeftPanelWidth}
          filters={filters}
          onFilterChange={handleFilterChange}
          summary={data?.summary}
        />

        <div className="flex-1 relative bg-grid-pattern">
          {isLoading ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-foreground-muted text-lg">Loading...</div>
            </div>
          ) : error ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-red-500 text-lg">{error}</div>
            </div>
          ) : !data ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-6">
              <div className="flex flex-col items-center gap-2">
                <div className="w-16 h-16 rounded-2xl bg-accent-cyan/10 flex items-center justify-center mb-2">
                  <svg className="w-8 h-8 text-accent-cyan" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                </div>
                <h2 className="text-xl font-semibold text-foreground">No scan loaded</h2>
                <p className="text-sm text-foreground-muted max-w-xs text-center">
                  Load a scan result JSON to visualize plugin security findings as an interactive graph.
                </p>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={handleLoadClick}
                  className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-accent-cyan/15 text-accent-cyan rounded-lg hover:bg-accent-cyan/25 transition-colors border border-accent-cyan/30"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                  </svg>
                  Load JSON File
                </button>
                <button
                  onClick={handleLoadSample}
                  className="px-5 py-2.5 text-sm font-medium bg-surface text-foreground-secondary rounded-lg hover:bg-surface-hover transition-colors border border-border"
                >
                  Load Sample Data
                </button>
              </div>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onSelectionChange={onSelectionChange}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              fitView
              fitViewOptions={{ padding: 0.2, maxZoom: 1 }}
              minZoom={0.2}
              maxZoom={1.5}
              defaultEdgeOptions={{ type: 'security' }}
              proOptions={{ hideAttribution: true }}
              nodesDraggable={true}
              nodesConnectable={false}
              elementsSelectable={true}
              selectNodesOnDrag={false}
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={30}
                size={1}
                color="var(--rf-dot-color)"
              />
              <Controls
                className="!bg-transparent !border-0 !shadow-none"
                showInteractive={false}
              />
              <MiniMap
                nodeStrokeWidth={2}
                nodeStrokeColor={(node) => {
                  const severity = (node.data as NodeData)?.severity || 'clean';
                  const colors: Record<string, string> = {
                    critical: '#ef4444',
                    high: '#f97316',
                    medium: '#eab308',
                    low: '#475569',
                    clean: '#334155',
                  };
                  return colors[severity] || '#334155';
                }}
                nodeColor={(node) => {
                  const severity = (node.data as NodeData)?.severity || 'clean';
                  const colors: Record<string, string> = {
                    critical: 'rgba(239, 68, 68, 0.5)',
                    high: 'rgba(249, 115, 22, 0.5)',
                    medium: 'rgba(234, 179, 8, 0.4)',
                    low: 'rgba(71, 85, 105, 0.4)',
                    clean: 'rgba(51, 65, 85, 0.4)',
                  };
                  return colors[severity] || 'rgba(51, 65, 85, 0.4)';
                }}
                pannable
                zoomable
              />
            </ReactFlow>
          )}
        </div>

        <Sidebar
          selectedNode={selectedNode}
          allNodes={(data?.nodes ?? []) as GraphNode[]}
          onSelectNode={handleSelectNode}
          isOpen={sidebarOpen}
        />
      </div>
    </div>
  );
}

export default App;
