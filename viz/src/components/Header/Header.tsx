import { useState, useRef, useEffect } from 'react';
import {
  Shield, ShieldCheck, ShieldAlert, Bug, Upload, Package, Zap,
  AlertTriangle, AlertCircle, Info, Sun, Moon,
  PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen,
  ChevronDown, Check,
} from 'lucide-react';
import type { ScanSummary, ScanType, Verdict, ScanListItem, AggregateSummary } from '../../types/plugin.types';
import type { Theme } from '../../hooks/useTheme';

interface HeaderProps {
  pluginName?: string;
  pluginVersion?: string;
  scanType?: ScanType;
  verdict?: Verdict;
  summary?: ScanSummary;
  onLoadClick: () => void;
  onLoadSample: () => void;
  theme: Theme;
  onToggleTheme: () => void;
  leftPanelOpen: boolean;
  onToggleLeftPanel: () => void;
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
  isMultiScan: boolean;
  scanList: ScanListItem[];
  activeScanIndex: number;
  onScanChange: (index: number) => void;
  aggregate?: AggregateSummary;
}

export function Header({
  pluginName,
  pluginVersion,
  scanType = 'plugin',
  verdict,
  summary,
  onLoadClick,
  onLoadSample,
  theme,
  onToggleTheme,
  leftPanelOpen,
  onToggleLeftPanel,
  sidebarOpen,
  onToggleSidebar,
  isMultiScan,
  scanList,
  activeScanIndex,
  onScanChange,
  aggregate,
}: HeaderProps) {
  const isSkill = scanType === 'skill';
  const titleText = isMultiScan
    ? 'Security Scanner'
    : isSkill
      ? 'Skill Security Scanner'
      : 'Plugin Security Scanner';
  const NameIcon = isSkill ? Zap : Package;

  return (
    <header className="relative z-50 h-16 px-6 flex items-center justify-between border-b border-border bg-background-elevated/80 backdrop-blur-sm">
      {/* Logo, title, and scan selector */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-accent-cyan/15 flex items-center justify-center flex-shrink-0">
          <Shield className="w-6 h-6 text-accent-cyan" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-foreground">{titleText}</h1>
          {!isMultiScan && pluginName && (
            <div className="flex items-center gap-2 text-sm text-foreground-secondary">
              <NameIcon className="w-3.5 h-3.5" />
              <span className="font-mono">{pluginName}</span>
              {pluginVersion && (
                <span className="px-1.5 py-0.5 text-xs bg-surface rounded font-mono">
                  v{pluginVersion}
                </span>
              )}
            </div>
          )}
        </div>

        {isMultiScan && scanList.length > 1 && (
          <>
            <div className="h-8 w-px bg-border" />
            <ScanSelector
              scanList={scanList}
              activeScanIndex={activeScanIndex}
              onScanChange={onScanChange}
            />
          </>
        )}

        {isMultiScan && aggregate && (
          <div className={`ml-2 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold ${
            aggregate.unsafeCount === 0
              ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
              : 'bg-red-500/10 text-red-500 border border-red-500/20'
          }`}>
            {aggregate.unsafeCount === 0
              ? <ShieldCheck className="w-3.5 h-3.5" />
              : <ShieldAlert className="w-3.5 h-3.5" />
            }
            {aggregate.safeCount}/{aggregate.totalScans} safe
          </div>
        )}

        {!isMultiScan && verdict && (
          <div className={`ml-4 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-semibold ${
            verdict.safe
              ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
              : 'bg-red-500/10 text-red-500 border border-red-500/20'
          }`}>
            {verdict.safe
              ? <ShieldCheck className="w-4 h-4" />
              : <ShieldAlert className="w-4 h-4" />
            }
            {verdict.safe ? 'SAFE' : `UNSAFE`}
            {!verdict.safe && verdict.malicious_count > 0 && (
              <span className="text-xs font-normal ml-1 opacity-80">
                ({verdict.malicious_count} malicious)
              </span>
            )}
          </div>
        )}
      </div>

      {/* Summary stats */}
      {summary && (
        <div className="flex items-center gap-6">
          <SummaryBadge
            icon={<AlertTriangle className="w-4 h-4" />}
            label="Critical"
            count={summary.critical}
            color="critical"
          />
          <SummaryBadge
            icon={<AlertCircle className="w-4 h-4" />}
            label="High"
            count={summary.high}
            color="high"
          />
          <SummaryBadge
            icon={<AlertCircle className="w-4 h-4" />}
            label="Medium"
            count={summary.medium}
            color="medium"
          />
          <SummaryBadge
            icon={<Info className="w-4 h-4" />}
            label="Low"
            count={summary.low}
            color="low"
          />
          <div className="h-8 w-px bg-border" />
          <SummaryBadge
            icon={<ShieldAlert className="w-4 h-4" />}
            label="Malicious"
            count={summary.malicious}
            color="malicious"
          />
          <SummaryBadge
            icon={<Bug className="w-4 h-4" />}
            label="Code Security"
            count={summary.codeSecurity}
            color="codeSecurity"
          />
          <div className="h-8 w-px bg-border" />
          <div className="text-sm text-foreground-secondary">
            <span className="font-semibold text-foreground">{summary.totalFindings}</span> findings
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={onLoadSample}
          className="px-3 py-2 text-sm text-foreground-muted hover:text-foreground-secondary transition-colors rounded-lg hover:bg-surface"
        >
          Load Sample
        </button>
        <button
          onClick={onLoadClick}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-accent-cyan bg-accent-cyan/10 hover:bg-accent-cyan/20 rounded-lg transition-colors border border-accent-cyan/30"
        >
          <Upload className="w-4 h-4" />
          Load JSON
        </button>

        <div className="h-8 w-px bg-border ml-1" />

        <button
          onClick={onToggleLeftPanel}
          className="p-2 rounded-lg text-foreground-muted hover:text-foreground-secondary hover:bg-surface transition-colors"
          title={leftPanelOpen ? 'Collapse filters' : 'Expand filters'}
        >
          {leftPanelOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />}
        </button>

        <button
          onClick={onToggleTheme}
          className="p-2 rounded-lg text-foreground-muted hover:text-foreground-secondary hover:bg-surface transition-colors"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-lg text-foreground-muted hover:text-foreground-secondary hover:bg-surface transition-colors"
          title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        >
          {sidebarOpen ? <PanelRightClose className="w-4 h-4" /> : <PanelRightOpen className="w-4 h-4" />}
        </button>
      </div>
    </header>
  );
}


/* ── Scan selector dropdown ── */

interface ScanSelectorProps {
  scanList: ScanListItem[];
  activeScanIndex: number;
  onScanChange: (index: number) => void;
}

function ScanSelector({ scanList, activeScanIndex, onScanChange }: ScanSelectorProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const active = scanList[activeScanIndex];
  if (!active) return null;

  const ItemIcon = active.scanType === 'skill' ? Zap : Package;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-hover transition-colors text-sm"
      >
        <ItemIcon className="w-3.5 h-3.5 text-foreground-secondary" />
        <span className="font-mono text-foreground max-w-[180px] truncate">{active.name}</span>
        {active.verdict && (
          active.verdict.safe
            ? <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            : <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
        )}
        <ChevronDown className={`w-3.5 h-3.5 text-foreground-muted transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute top-full left-0 mt-1 w-72 max-h-80 overflow-y-auto rounded-lg border border-border bg-background-elevated shadow-lg z-50">
          {scanList.map((item) => {
            const Icon = item.scanType === 'skill' ? Zap : Package;
            const isActive = item.index === activeScanIndex;
            return (
              <button
                key={item.index}
                onClick={() => { onScanChange(item.index); setOpen(false); }}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-sm text-left hover:bg-surface transition-colors ${
                  isActive ? 'bg-surface' : ''
                }`}
              >
                <Icon className="w-4 h-4 text-foreground-secondary flex-shrink-0" />
                <span className="flex-1 font-mono truncate text-foreground">{item.name}</span>
                <span className="text-xs text-foreground-muted capitalize">{item.scanType}</span>
                {item.verdict && (
                  item.verdict.safe
                    ? <ShieldCheck className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                    : <ShieldAlert className="w-4 h-4 text-red-500 flex-shrink-0" />
                )}
                {isActive && <Check className="w-4 h-4 text-accent-cyan flex-shrink-0" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}


/* ── Summary badge ── */

interface SummaryBadgeProps {
  icon: React.ReactNode;
  label: string;
  count: number;
  color: 'critical' | 'high' | 'medium' | 'low' | 'malicious' | 'codeSecurity';
}

function SummaryBadge({ icon, label, count, color }: SummaryBadgeProps) {
  const colorClasses: Record<string, string> = {
    critical: 'text-red-500',
    high: 'text-orange-500',
    medium: 'text-yellow-500',
    low: 'text-foreground-muted',
    malicious: 'text-rose-500',
    codeSecurity: 'text-sky-500',
  };

  if (count === 0) return null;

  return (
    <div className={`flex items-center gap-1.5 ${colorClasses[color]}`}>
      {icon}
      <span className="text-sm font-medium">{count}</span>
      <span className="text-xs text-foreground-muted">{label}</span>
    </div>
  );
}
