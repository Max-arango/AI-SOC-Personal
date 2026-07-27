import { useEffect, useRef, useState, useCallback } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import {
  Filter, X, ChevronDown, ChevronRight, ArrowUp,
} from 'lucide-react';
import { cn, formatRelativeTime, getSeverityColor } from '../utils/cn';
import { useInfiniteEvents } from '../hooks/useInfiniteEvents';

const SOURCE_OPTIONS = ['', 'process', 'network', 'file', 'registry', 'usb', 'browser', 'startup'];

export default function Events() {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [filterType, setFilterType] = useState('');
  const [filterSource, setFilterSource] = useState('');
  const [filterMinRisk, setFilterMinRisk] = useState<number>(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const {
    items,
    totalCount,
    hasMore,
    loading,
    loadingMore,
    error,
    newEventCount,
    loadMore,
    refresh,
    dismissNewEvents,
    startPolling,
    stopPolling,
    fetchPage,
  } = useInfiniteEvents({
    eventTypes: filterType ? [filterType] : undefined,
    sources: filterSource ? [filterSource] : undefined,
    minRiskScore: filterMinRisk > 0 ? filterMinRisk : undefined,
  });

  const parentRef = useRef<HTMLDivElement>(null);
  const scrollRestoreRef = useRef<number>(0);

  useEffect(() => {
    fetchPage(true);
    startPolling(5000);
    return () => stopPolling();
  }, []);

  useEffect(() => {
    refresh();
  }, [filterType, filterSource, filterMinRisk]);

  const rowVirtualizer = useVirtualizer({
    count: hasMore ? items.length + 1 : items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 48,
    overscan: 5,
  });

  const handleScroll = useCallback(() => {
    if (parentRef.current) {
      scrollRestoreRef.current = parentRef.current.scrollTop;
    }
  }, []);

  useEffect(() => {
    const el = parentRef.current;
    if (!el) return;
    el.addEventListener('scroll', handleScroll, { passive: true });
    return () => el.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);

  const loadMoreIfNeeded = useCallback(() => {
    if (!parentRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = parentRef.current;
    if (scrollHeight - scrollTop - clientHeight < 200 && hasMore && !loadingMore) {
      loadMore();
    }
  }, [hasMore, loadingMore, loadMore]);

  useEffect(() => {
    const el = parentRef.current;
    if (!el) return;
    const onScroll = () => loadMoreIfNeeded();
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => el.removeEventListener('scroll', onScroll);
  }, [loadMoreIfNeeded]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Events</h1>
          <p className="text-gray-500 dark:text-gray-400">
            {loading ? 'Loading...' : `${totalCount.toLocaleString()} events recorded`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setFiltersOpen(!filtersOpen)}
            className={cn(
              'flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
              filtersOpen
                ? 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
                : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300 border border-gray-300 dark:border-gray-600',
            )}
          >
            <Filter className="h-4 w-4" />
            Filters
          </button>
          <button
            onClick={refresh}
            disabled={loading}
            className="rounded-lg bg-primary-600 px-3 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
          >
            Refresh
          </button>
        </div>
      </div>

      {filtersOpen && (
        <div className="card p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Event Type</label>
            <input
              type="text"
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              placeholder="e.g. sentinel.process.create"
              className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Source</label>
            <select
              value={filterSource}
              onChange={(e) => setFilterSource(e.target.value)}
              className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
            >
              {SOURCE_OPTIONS.map((s) => (
                <option key={s} value={s}>{s || 'All'}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Min Risk</label>
            <input
              type="number"
              value={filterMinRisk || ''}
              onChange={(e) => setFilterMinRisk(Number(e.target.value) || 0)}
              placeholder="0"
              min={0}
              max={1000}
              className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={() => {
                setFilterType('');
                setFilterSource('');
                setFilterMinRisk(0);
              }}
              className="flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            >
              <X className="h-3.5 w-3.5" /> Clear filters
            </button>
          </div>
        </div>
      )}

      {newEventCount > 0 && (
        <button
          onClick={dismissNewEvents}
          className="flex items-center gap-2 mx-auto rounded-full bg-primary-600 text-white px-4 py-1.5 text-sm font-medium shadow-lg hover:bg-primary-700 transition-all animate-bounce"
        >
          <ArrowUp className="h-3.5 w-3.5" />
          {newEventCount} new events — click to refresh
        </button>
      )}

      {error && (
        <div className="rounded-lg border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-4">
          <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
          <button onClick={refresh} className="mt-2 text-sm font-medium text-red-600 hover:text-red-800">Retry</button>
        </div>
      )}

      <div className="card">
        {loading && items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-gray-400">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-primary-600" />
            <p className="mt-3 text-sm">Loading events...</p>
          </div>
        ) : (
          <div ref={parentRef} className="overflow-auto" style={{ height: 'calc(100vh - 280px)', minHeight: 400 }}>
            <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, position: 'relative' }}>
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const isLoader = virtualRow.index >= items.length;

                if (isLoader) {
                  return (
                    <div
                      key="loader"
                      style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        width: '100%',
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                      className="flex items-center justify-center py-4"
                    >
                      {hasMore ? (
                        <div className="flex items-center gap-2 text-sm text-gray-400">
                          <div className="h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-primary-600" />
                          Loading more events...
                        </div>
                      ) : (
                        <p className="text-sm text-gray-400">
                          {items.length > 0 ? `${totalCount.toLocaleString()} total events` : ''}
                        </p>
                      )}
                    </div>
                  );
                }

                const evt = items[virtualRow.index] as any;
                if (!evt) return null;

                const id = evt.id ?? `row-${virtualRow.index}`;
                const isExpanded = expandedId === id;

                return (
                  <div
                    key={id}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                  >
                    <div
                      onClick={() => toggleExpand(id)}
                      className={cn(
                        'flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors border-b border-gray-100 dark:border-gray-700/50',
                        virtualRow.index % 2 === 0
                          ? 'bg-white dark:bg-gray-800'
                          : 'bg-gray-50 dark:bg-gray-800/50',
                        'hover:bg-blue-50 dark:hover:bg-blue-900/20',
                      )}
                      style={{ height: 48 }}
                    >
                      <div className="flex-shrink-0 w-5">
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4 text-gray-400" />
                        ) : (
                          <ChevronRight className="h-4 w-4 text-gray-400" />
                        )}
                      </div>
                      <span className={cn('badge flex-shrink-0', getSeverityColor(String(evt.severity ?? 'info')))}>
                        {['', 'DBG', 'INF', 'NOT', 'WAR', 'ERR', 'CRI', 'ALT', 'EMG'][evt.severity as number] ?? 'INF'}
                      </span>
                      <span className="flex-1 font-mono text-sm text-gray-900 dark:text-white truncate">
                        {evt.type ?? 'Unknown'}
                        {evt.process?.name ? (
                          <span className="text-gray-400 dark:text-gray-500 ml-2 text-xs">
                            [{evt.process.name}]
                          </span>
                        ) : null}
                      </span>
                      <span className="flex-shrink-0 text-xs text-gray-400 dark:text-gray-500 w-16 text-right">
                        {evt.source ?? '-'}
                      </span>
                      <span className={cn(
                        'flex-shrink-0 badge text-xs w-16 text-center',
                        (evt.risk_score ?? 0) > 100
                          ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                          : (evt.risk_score ?? 0) > 50
                          ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300'
                          : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
                      )}>
                        {evt.risk_score ?? 0}
                      </span>
                      <span className="flex-shrink-0 text-xs text-gray-400 dark:text-gray-500 w-24 text-right">
                        {evt.timestamp ? formatRelativeTime(new Date((evt.timestamp as number) * 1000).toISOString()) : '-'}
                      </span>
                    </div>

                    {isExpanded && (
                      <div className="bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700 px-10 py-3">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                          <div>
                            <span className="text-gray-400">ID: </span>
                            <span className="font-mono text-gray-600 dark:text-gray-300">{evt.id}</span>
                          </div>
                          <div>
                            <span className="text-gray-400">Host: </span>
                            <span className="font-mono text-gray-600 dark:text-gray-300">{evt.host_id ?? '-'}</span>
                          </div>
                          {evt.process ? (
                            <>
                              <div className="col-span-full mt-1 pt-2 border-t border-gray-200 dark:border-gray-700">
                                <span className="text-gray-400 font-medium">Process</span>
                              </div>
                              <div><span className="text-gray-400">PID: </span>{evt.process.pid}</div>
                              <div><span className="text-gray-400">PPID: </span>{evt.process.ppid}</div>
                              <div className="col-span-full">
                                <span className="text-gray-400">Exe: </span>
                                <span className="font-mono text-gray-600 dark:text-gray-300">{evt.process.path ?? '-'}</span>
                              </div>
                              {evt.process.command_line && (
                                <div className="col-span-full">
                                  <span className="text-gray-400">Cmd: </span>
                                  <span className="font-mono text-gray-600 dark:text-gray-300 break-all">{evt.process.command_line}</span>
                                </div>
                              )}
                            </>
                          ) : null}
                          {evt.tags?.length > 0 && (
                            <div className="col-span-full mt-1">
                              <span className="text-gray-400">Tags: </span>
                              <span className="text-gray-600 dark:text-gray-300">
                                {evt.tags.join(', ')}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
