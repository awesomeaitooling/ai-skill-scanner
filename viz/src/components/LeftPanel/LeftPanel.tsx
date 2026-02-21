import { useCallback, useRef, useEffect } from 'react';
import { FilterPanel } from '../Sidebar/FilterPanel';
import type { FilterState, ScanSummary } from '../../types/plugin.types';

const MIN_WIDTH = 200;
const MAX_WIDTH = 400;

interface LeftPanelProps {
  isOpen: boolean;
  width: number;
  onWidthChange: (width: number) => void;
  filters: FilterState;
  onFilterChange: (filters: FilterState) => void;
  summary?: ScanSummary;
}

export function LeftPanel({
  isOpen,
  width,
  onWidthChange,
  filters,
  onFilterChange,
  summary,
}: LeftPanelProps) {
  const isDragging = useRef(false);
  const panelRef = useRef<HTMLDivElement>(null);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    isDragging.current = true;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging.current) return;
      const newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, e.clientX));
      onWidthChange(newWidth);
    };

    const handleMouseUp = () => {
      if (!isDragging.current) return;
      isDragging.current = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [onWidthChange]);

  return (
    <aside
      ref={panelRef}
      className="relative flex-shrink-0 h-full border-r border-border bg-background-elevated/50 backdrop-blur-sm transition-[width] duration-200 ease-in-out overflow-hidden"
      style={{ width: isOpen ? width : 0, minWidth: isOpen ? MIN_WIDTH : 0 }}
    >
      <div className="h-full overflow-y-auto" style={{ minWidth: MIN_WIDTH }}>
        <FilterPanel filters={filters} onChange={onFilterChange} summary={summary} />
      </div>

      {/* Resize handle */}
      {isOpen && (
        <div
          onMouseDown={handleMouseDown}
          className="absolute top-0 right-0 w-1.5 h-full cursor-col-resize group z-10 flex items-center justify-center"
        >
          <div className="w-px h-full bg-border group-hover:bg-accent-cyan/50 transition-colors" />
        </div>
      )}
    </aside>
  );
}
