import { useCallback, useEffect, useRef, useState } from 'react';

/** Minimal loader for screen data: initial load, pull-to-refresh and error state. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const mounted = useRef(true);

  const run = useCallback(async (mode: 'load' | 'refresh' = 'load') => {
    mode === 'refresh' ? setRefreshing(true) : setLoading(true);
    try {
      const d = await fn();
      if (mounted.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (mounted.current) setError((e as Error).message);
    } finally {
      if (mounted.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    mounted.current = true;
    void run();
    return () => {
      mounted.current = false;
    };
  }, [run]);

  return { data, setData, error, loading, refreshing, reload: () => run('load'), refresh: () => run('refresh') };
}
