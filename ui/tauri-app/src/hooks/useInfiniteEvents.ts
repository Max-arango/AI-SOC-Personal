import { useRef, useCallback, useState } from 'react';
import * as api from '../utils/tauriApi';

const PAGE_SIZE = 100;

interface UseInfiniteEventsOptions {
  eventTypes?: string[];
  sources?: string[];
  minRiskScore?: number;
  startTime?: string;
  endTime?: string;
}

export function useInfiniteEvents(options: UseInfiniteEventsOptions = {}) {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newEventCount, setNewEventCount] = useState(0);

  const offsetRef = useRef(0);
  const latestTimestamp = useRef<number>(0);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchPage = useCallback(
    async (reset = false) => {
      if (reset) {
        offsetRef.current = 0;
        setHasMore(true);
        setLoading(true);
      } else {
        setLoadingMore(true);
      }

      setError(null);

      try {
        const result = await api.queryEvents({
          event_types: options.eventTypes?.length ? options.eventTypes : undefined,
          sources: options.sources?.length ? options.sources : undefined,
          min_risk_score: options.minRiskScore || undefined,
          start_time: options.startTime || undefined,
          end_time: options.endTime || undefined,
          limit: PAGE_SIZE,
          offset: reset ? 0 : offsetRef.current,
        });

        if (reset) {
          setItems(result.events);
        } else {
          setItems((prev) => [...prev, ...result.events]);
        }

        setTotalCount(result.total_count);
        setHasMore(result.has_more);
        offsetRef.current += result.events.length;

        if (result.events.length > 0) {
          const lastEvt = result.events[result.events.length - 1];
          if (lastEvt && (lastEvt as any).timestamp) {
            latestTimestamp.current = (lastEvt as any).timestamp;
          }
        }
      } catch (e: any) {
        setError(String(e));
      } finally {
        setLoading(false);
        setLoadingMore(false);
      }
    },
    [options.eventTypes, options.sources, options.minRiskScore, options.startTime, options.endTime],
  );

  const loadMore = useCallback(() => {
    if (!loadingMore && hasMore) {
      fetchPage(false);
    }
  }, [loadingMore, hasMore, fetchPage]);

  const refresh = useCallback(() => {
    fetchPage(true);
  }, [fetchPage]);

  const startPolling = useCallback(
    (intervalMs = 5000) => {
      if (pollingRef.current) return;
      pollingRef.current = setInterval(async () => {
        if (latestTimestamp.current === 0) return;
        try {
          const result = await api.queryEvents({
            ...options,
            limit: 1,
            offset: 0,
          });
          if (result.events.length > 0) {
            const firstTs = (result.events[0] as any).timestamp as number;
            if (firstTs > latestTimestamp.current) {
              setNewEventCount((c) => c + 1);
            }
          }
        } catch {
          // silent
        }
      }, intervalMs);
    },
    [options],
  );

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const dismissNewEvents = useCallback(() => {
    setNewEventCount(0);
    refresh();
  }, [refresh]);

  return {
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
  };
}
