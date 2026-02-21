import type { Severity, Section } from '../../types/plugin.types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

const severityConfig: Record<Severity, { bg: string; text: string; border: string; label: string }> = {
  critical: {
    bg: 'bg-red-500/15',
    text: 'text-red-500',
    border: 'border-red-500/25',
    label: 'Critical',
  },
  high: {
    bg: 'bg-orange-500/15',
    text: 'text-orange-500',
    border: 'border-orange-500/25',
    label: 'High',
  },
  medium: {
    bg: 'bg-yellow-500/15',
    text: 'text-yellow-600',
    border: 'border-yellow-500/25',
    label: 'Medium',
  },
  low: {
    bg: 'bg-slate-500/15',
    text: 'text-slate-500',
    border: 'border-slate-500/25',
    label: 'Low',
  },
  clean: {
    bg: 'bg-emerald-500/15',
    text: 'text-emerald-600',
    border: 'border-emerald-500/25',
    label: 'Clean',
  },
};

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  const sizeClasses = size === 'sm'
    ? 'px-1.5 py-0 text-[10px]'
    : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center rounded-full font-medium border ${config.bg} ${config.text} ${config.border} ${sizeClasses}`}
    >
      {config.label}
    </span>
  );
}

interface TypeBadgeProps {
  type: string;
}

export function TypeBadge({ type }: TypeBadgeProps) {
  return (
    <span className="inline-flex items-center rounded-full text-xs font-medium bg-surface text-foreground-secondary border border-border">
      {type}
    </span>
  );
}

// Section badge
const sectionConfig: Record<Section, { bg: string; text: string; border: string; label: string }> = {
  malicious: {
    bg: 'bg-rose-500/15',
    text: 'text-rose-500',
    border: 'border-rose-500/25',
    label: 'Malicious',
  },
  code_security: {
    bg: 'bg-sky-500/15',
    text: 'text-sky-500',
    border: 'border-sky-500/25',
    label: 'Code Security',
  },
};

interface SectionBadgeProps {
  section: Section;
  size?: 'sm' | 'md';
}

export function SectionBadge({ section, size = 'md' }: SectionBadgeProps) {
  const config = sectionConfig[section];

  const sizeClasses = size === 'sm'
    ? 'px-1.5 py-0 text-[10px]'
    : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center rounded-full font-medium border ${config.bg} ${config.text} ${config.border} ${sizeClasses}`}
    >
      {config.label}
    </span>
  );
}

// Category badge (mono-styled chip)
interface CategoryBadgeProps {
  category: string;
}

export function CategoryBadge({ category }: CategoryBadgeProps) {
  return (
    <code className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-surface text-foreground-secondary border border-border">
      {category}
    </code>
  );
}
