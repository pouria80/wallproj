import { useEffect, useState } from 'react';

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    setLoading(true); setError(null);
    fn().then(d => alive && setData(d)).catch(e => alive && setError(String(e.message ?? e)))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, loading, reload: () => fn().then(setData).catch(e => setError(String(e))) };
}

export function Badge({ s }: { s: string }) {
  return <span className={`badge ${s}`}>{s}</span>;
}

export function State({ loading, error, empty, children }:
  { loading: boolean; error: string | null; empty?: boolean; children: React.ReactNode }) {
  if (loading) return <div className="card muted">Loading…</div>;
  if (error) return <div className="errbox">Error: {error}</div>;
  if (empty) return <div className="empty">No data yet — nothing has been fabricated.</div>;
  return <>{children}</>;
}

export function Json({ v, max = 4000 }: { v: unknown; max?: number }) {
  const text = typeof v === 'string' ? v : JSON.stringify(v, null, 2) ?? 'null';
  return <pre className="code">{text.length > max ? text.slice(0, max) + `\n… [truncated ${text.length - max} chars]` : text}</pre>;
}
