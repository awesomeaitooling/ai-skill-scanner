import { useState, useCallback } from 'react';
import {
  ScanResult, SAMPLE_DATA, GraphNode, GraphEdge, NodeType, Severity, Section,
  Finding, ScanType, Verdict, AggregateSummary, MultiScanResult, ScanListItem,
} from '../types/plugin.types';

// Layout constants for auto-generating graph from flat JSON report
const LAYOUT = {
  rootX: 500,
  rootY: 50,
  hSpacing: 200,
  vSpacing: 140,
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

const ALL_NODE_TYPES: NodeType[] = ['plugin', 'skill', 'command', 'hook', 'mcp', 'lsp', 'agent', 'script', 'resource'];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#6b7280',
  clean: '#22c55e',
};

/**
 * Detect if the JSON is a flat scanner report (not a graph export) and convert it
 * to the ScanResult graph format the UI expects.
 *
 * Flat reports have: metadata, plugin, summary, findings, components, errors
 * Graph exports have: plugin, nodes, edges, summary, nodeTypes, severityColors
 */
function convertFlatReportToGraph(raw: Record<string, unknown>): ScanResult | null {
  // Must have `plugin` and either `findings` or `components` but NOT `nodes`
  if (!raw.plugin || raw.nodes) return null;
  if (!raw.findings && !raw.components) return null;

  const pluginInfo = raw.plugin as { name?: string; version?: string; description?: string; author?: unknown };
  const flatFindings = (raw.findings || []) as Array<{
    severity?: string;
    section?: string;
    category?: string;
    rule_id?: string;
    rule_name?: string;
    message?: string;
    component_type?: string;
    component_name?: string;
    component_path?: string;
    line?: number;
    snippet?: string;
    recommendation?: string;
  }>;
  const componentsInfo = raw.components as { total?: number; by_type?: Record<string, number> } | undefined;
  const summaryInfo = raw.summary as {
    total_findings?: number;
    severity_counts?: Record<string, number>;
    section_counts?: Record<string, number>;
  } | undefined;

  // Group findings by "type:name"
  const findingsByComponent: Record<string, typeof flatFindings> = {};
  for (const f of flatFindings) {
    const key = `${f.component_type || 'unknown'}:${f.component_name || 'unknown'}`;
    if (!findingsByComponent[key]) findingsByComponent[key] = [];
    findingsByComponent[key].push(f);
  }

  // Gather unique components from findings + component counts
  const componentSet = new Map<string, { type: NodeType; name: string; path: string }>();

  for (const f of flatFindings) {
    const cType = (f.component_type || 'skill') as NodeType;
    const cName = f.component_name || 'unknown';
    const key = `${cType}:${cName}`;
    if (!componentSet.has(key)) {
      componentSet.set(key, { type: cType, name: cName, path: f.component_path || '' });
    }
  }

  // Also add components from the by_type counts that may have no findings
  if (componentsInfo?.by_type) {
    for (const [type, count] of Object.entries(componentsInfo.by_type)) {
      const nodeType = type as NodeType;
      // Only add placeholder components if we have none of that type yet
      const existing = [...componentSet.values()].filter(c => c.type === nodeType).length;
      for (let i = existing; i < count; i++) {
        const name = `${type}-${i + 1}`;
        const key = `${type}:${name}`;
        if (!componentSet.has(key)) {
          componentSet.set(key, { type: nodeType, name, path: '' });
        }
      }
    }
  }

  // Helper to get highest severity from findings
  const getHighestSeverity = (findings: typeof flatFindings): Severity => {
    for (const s of SEVERITY_ORDER) {
      if (findings.some(f => f.severity === s)) return s;
    }
    return 'clean';
  };

  // Helper to convert flat finding to UI Finding
  const toFinding = (f: typeof flatFindings[0]): Finding => ({
    severity: (f.severity || 'medium') as Severity,
    section: (f.section || 'code_security') as Section,
    category: f.category || undefined,
    ruleId: f.rule_id || 'unknown',
    ruleName: f.rule_name || 'Unknown Rule',
    message: f.message || '',
    line: f.line,
    snippet: f.snippet,
    filePath: f.component_path,
    recommendation: f.recommendation,
  });

  // Build nodes
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // Component counts for root node
  const componentCounts: Record<NodeType, number> = {} as Record<NodeType, number>;
  for (const t of ALL_NODE_TYPES) componentCounts[t] = 0;
  componentCounts.plugin = 1;
  for (const c of componentSet.values()) {
    componentCounts[c.type] = (componentCounts[c.type] || 0) + 1;
  }

  // Detect scan type: skill-only if all non-manifest components are skills
  const componentTypes = new Set([...componentSet.values()].map(c => c.type));
  const nonSkillTypes = [...componentTypes].filter(t => t !== 'skill' && t !== 'resource');
  const hasManifest = Boolean(findingsByComponent['manifest:plugin.json']);
  const scanType: ScanType =
    !hasManifest && nonSkillTypes.length === 0 && componentTypes.has('skill')
      ? 'skill'
      : 'plugin';

  // Aggregate counts across ALL findings for root node
  const totalMalicious = flatFindings.filter(f => f.section === 'malicious').length;
  const totalCodeSecurity = flatFindings.filter(
    f => (f.section || 'code_security') === 'code_security',
  ).length;

  // Root node — manifest-level findings are its own, but severity and totals
  // reflect the entire scan
  const manifestFindings = findingsByComponent['manifest:plugin.json'] || [];
  const rootLabel = scanType === 'skill'
    ? (pluginInfo.name || 'standalone-skill')
    : (pluginInfo.name || 'unknown-plugin');

  nodes.push({
    id: 'plugin-root',
    type: scanType === 'skill' ? 'skill' : 'plugin',
    position: { x: LAYOUT.rootX, y: LAYOUT.rootY },
    data: {
      label: rootLabel,
      version: pluginInfo.version || '0.0.0',
      description: (pluginInfo.description as string) || '',
      severity: getHighestSeverity(flatFindings),
      findingsCount: manifestFindings.length,
      findings: manifestFindings.map(toFinding),
      componentCounts,
      totalFindings: flatFindings.length,
      totalMalicious,
      totalCodeSecurity,
    },
  });

  // Group components by type for row layout
  const byType: Record<string, Array<{ type: NodeType; name: string; path: string }>> = {};
  for (const c of componentSet.values()) {
    if (!byType[c.type]) byType[c.type] = [];
    byType[c.type].push(c);
  }

  let yOffset = LAYOUT.rootY + LAYOUT.vSpacing;

  for (const [typeName, comps] of Object.entries(byType)) {
    const totalWidth = (comps.length - 1) * LAYOUT.hSpacing;
    const startX = LAYOUT.rootX - totalWidth / 2;

    for (let i = 0; i < comps.length; i++) {
      const comp = comps[i];
      const key = `${comp.type}:${comp.name}`;
      const compFindings = findingsByComponent[key] || [];
      const severity = getHighestSeverity(compFindings);
      const nodeId = `${typeName}-${comp.name}`;

      nodes.push({
        id: nodeId,
        type: typeName as NodeType,
        position: { x: startX + i * LAYOUT.hSpacing, y: yOffset },
        data: {
          label: comp.name,
          path: comp.path,
          componentType: comp.type,
          severity,
          findingsCount: compFindings.length,
          findings: compFindings.map(toFinding),
          metadata: {},
        },
      });

      edges.push({
        id: `e-root-${nodeId}`,
        source: 'plugin-root',
        target: nodeId,
        type: 'security',
        animated: severity === 'critical' || severity === 'high',
        data: { severity },
      });
    }

    yOffset += LAYOUT.vSpacing;
  }

  // Build summary
  const sevCounts = summaryInfo?.severity_counts || {};
  const secCounts = summaryInfo?.section_counts || {};
  const summary = {
    totalFindings: summaryInfo?.total_findings ?? flatFindings.length,
    critical: sevCounts.critical ?? flatFindings.filter(f => f.severity === 'critical').length,
    high: sevCounts.high ?? flatFindings.filter(f => f.severity === 'high').length,
    medium: sevCounts.medium ?? flatFindings.filter(f => f.severity === 'medium').length,
    low: sevCounts.low ?? flatFindings.filter(f => f.severity === 'low').length,
    malicious: secCounts.malicious ?? flatFindings.filter(f => f.section === 'malicious').length,
    codeSecurity: secCounts.code_security ?? flatFindings.filter(f => (f.section || 'code_security') === 'code_security').length,
    totalComponents: componentsInfo?.total ?? componentSet.size,
    componentTypes: componentCounts,
  };

  const rawVerdict = raw.verdict as Verdict | undefined;
  const maliciousTotal = summary.malicious;
  const verdict: Verdict = rawVerdict ?? {
    safe: maliciousTotal === 0,
    summary: maliciousTotal === 0
      ? 'No malicious findings detected'
      : `UNSAFE: ${maliciousTotal} malicious finding(s) detected`,
    malicious_count: maliciousTotal,
  };

  return {
    plugin: {
      name: pluginInfo.name || 'unknown-plugin',
      version: pluginInfo.version || '0.0.0',
      path: (raw.metadata as { plugin_path?: string })?.plugin_path || '',
    },
    scanType,
    verdict,
    nodes,
    edges,
    summary,
    nodeTypes: ALL_NODE_TYPES,
    severityColors: SEVERITY_COLORS,
  };
}

/**
 * Parse a single graph-format or flat-format JSON object into a ScanResult.
 */
function parseSingleScan(jsonData: Record<string, unknown>): ScanResult | null {
  if (jsonData.plugin && jsonData.nodes && jsonData.edges) {
    const result = jsonData as unknown as ScanResult;
    if (!result.scanType) {
      const rawScanType = (jsonData as Record<string, unknown>).scanType as string | undefined;
      if (rawScanType === 'skill' || rawScanType === 'plugin') {
        result.scanType = rawScanType;
      } else {
        const hasPluginRoot = (result.nodes as GraphNode[]).some(n => n.type === 'plugin');
        result.scanType = hasPluginRoot ? 'plugin' : 'skill';
      }
    }
    if (!result.verdict && result.summary) {
      const mal = result.summary.malicious ?? 0;
      result.verdict = {
        safe: mal === 0,
        summary: mal === 0
          ? 'No malicious findings detected'
          : `UNSAFE: ${mal} malicious finding(s) detected`,
        malicious_count: mal,
      };
    }
    return result;
  }

  return convertFlatReportToGraph(jsonData);
}

interface UsePluginDataReturn {
  data: ScanResult | null;
  isLoading: boolean;
  error: string | null;
  loadFromFile: (jsonData: Record<string, unknown>) => void;
  loadFromUrl: (url: string) => Promise<void>;
  loadSampleData: () => void;
  clear: () => void;
  isMultiScan: boolean;
  multiData: MultiScanResult | null;
  activeScanIndex: number;
  setActiveScan: (index: number) => void;
  scanList: ScanListItem[];
}

export function usePluginData(): UsePluginDataReturn {
  const [data, setData] = useState<ScanResult | null>(null);
  const [multiData, setMultiData] = useState<MultiScanResult | null>(null);
  const [activeScanIndex, setActiveScanIndex] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isMultiScan = multiData !== null;

  const scanList: ScanListItem[] = multiData
    ? multiData.scans.map((s, i) => ({
        index: i,
        name: s.plugin.name,
        scanType: s.scanType,
        verdict: s.verdict,
      }))
    : data
      ? [{ index: 0, name: data.plugin.name, scanType: data.scanType, verdict: data.verdict }]
      : [];

  const setActiveScan = useCallback((index: number) => {
    if (!multiData || index < 0 || index >= multiData.scans.length) return;
    setActiveScanIndex(index);
    setData(multiData.scans[index]);
  }, [multiData]);

  const loadFromFile = useCallback((jsonData: Record<string, unknown>) => {
    setIsLoading(true);
    setError(null);
    setMultiData(null);
    setActiveScanIndex(0);

    try {
      // Detect multi-scan format
      if (jsonData.multi_scan === true && Array.isArray(jsonData.scans)) {
        const rawScans = jsonData.scans as Array<Record<string, unknown>>;
        const parsedScans: ScanResult[] = [];

        for (const rawScan of rawScans) {
          const parsed = parseSingleScan(rawScan);
          if (parsed) {
            parsedScans.push(parsed);
          }
        }

        if (parsedScans.length === 0) {
          throw new Error('Multi-scan file contained no valid scan results.');
        }

        const rawAggregate = jsonData.aggregate as Record<string, number> | undefined;
        const aggregate: AggregateSummary = {
          totalScans: rawAggregate?.total_scans ?? parsedScans.length,
          safeCount: rawAggregate?.safe_count ?? parsedScans.filter(s => s.verdict?.safe).length,
          unsafeCount: rawAggregate?.unsafe_count ?? parsedScans.filter(s => !s.verdict?.safe).length,
          totalFindings: rawAggregate?.total_findings ?? parsedScans.reduce((a, s) => a + s.summary.totalFindings, 0),
          totalMalicious: rawAggregate?.total_malicious ?? parsedScans.reduce((a, s) => a + s.summary.malicious, 0),
          totalCodeSecurity: rawAggregate?.total_code_security ?? parsedScans.reduce((a, s) => a + s.summary.codeSecurity, 0),
        };

        const multi: MultiScanResult = {
          multiScan: true,
          aggregate,
          scans: parsedScans,
        };

        setMultiData(multi);
        setActiveScanIndex(0);
        setData(parsedScans[0]);
        return;
      }

      // Single scan
      const result = parseSingleScan(jsonData);
      if (result) {
        setData(result);
        return;
      }

      throw new Error(
        'Unsupported scan result format. Use --output graph when running the scanner, ' +
        'or the flat JSON report format with plugin/findings/components fields.'
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loadFromUrl = useCallback(async (url: string) => {
    setIsLoading(true);
    setError(null);

    const MAX_RESPONSE_BYTES = 50 * 1024 * 1024; // 50 MB

    try {
      const parsed = new URL(url, window.location.origin);
      if (parsed.origin !== window.location.origin) {
        throw new Error(
          `Blocked fetch to external origin: ${parsed.origin}. Only same-origin URLs are allowed.`
        );
      }

      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
        throw new Error(`Response too large (${contentLength} bytes, max ${MAX_RESPONSE_BYTES})`);
      }

      const text = await response.text();
      if (text.length > MAX_RESPONSE_BYTES) {
        throw new Error(`Response body too large (max ${MAX_RESPONSE_BYTES} bytes)`);
      }

      const jsonData = JSON.parse(text);
      loadFromFile(jsonData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
      setIsLoading(false);
    }
  }, [loadFromFile]);

  const loadSampleData = useCallback(() => {
    setIsLoading(true);
    setError(null);
    setMultiData(null);
    setActiveScanIndex(0);

    setTimeout(() => {
      setData(SAMPLE_DATA);
      setIsLoading(false);
    }, 300);
  }, []);

  const clear = useCallback(() => {
    setData(null);
    setMultiData(null);
    setActiveScanIndex(0);
    setError(null);
  }, []);

  return {
    data,
    isLoading,
    error,
    loadFromFile,
    loadFromUrl,
    loadSampleData,
    clear,
    isMultiScan,
    multiData,
    activeScanIndex,
    setActiveScan,
    scanList,
  };
}

