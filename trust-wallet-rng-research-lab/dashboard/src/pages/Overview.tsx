import { Link } from 'react-router-dom';
import { api } from '../api';
import { State, useAsync, Badge } from '../components/ui';

export default function Overview() {
  const { data: ov, error, loading } = useAsync(api.overview, []);
  return (
    <State loading={loading} error={error}>
      {ov && (<>
        <div className="grid cols-4">
          <Link to="/runs" className="card"><div className="label">Runs total</div><div className="stat">{ov.runs_total}</div></Link>
          <Link to="/runs?status=completed" className="card"><div className="label">Completed</div><div className="stat" style={{ color: 'var(--ok)' }}>{ov.runs_by_status.completed ?? 0}</div></Link>
          <Link to="/runs?status=failed" className="card"><div className="label">Failed</div><div className="stat" style={{ color: 'var(--err)' }}>{ov.runs_by_status.failed ?? 0}</div></Link>
          <Link to="/runs" className="card"><div className="label">Queued / running</div><div className="stat" style={{ color: 'var(--accent)' }}>{(ov.runs_by_status.queued ?? 0) + (ov.runs_by_status.running ?? 0)}</div></Link>
          <Link to="/experiments" className="card"><div className="label">Experiment definitions</div><div className="stat">{ov.experiments_defined}</div></Link>
          <Link to="/rng-research" className="card"><div className="label">Runnable core experiments</div><div className="stat">{ov.core_experiments_available}</div></Link>
          <Link to="/wallet-lab" className="card"><div className="label">Samples</div><div className="stat">{ov.samples}</div></Link>
          <Link to="/findings" className="card"><div className="label">Findings</div><div className="stat">{ov.findings}</div></Link>
          <Link to="/evidence" className="card"><div className="label">Evidence records</div><div className="stat">{ov.evidence_records}</div></Link>
          <Link to="/evidence" className="card"><div className="label">Snapshot integrity</div>
            <div className="stat" style={{ color: ov.snapshot_integrity.ok ? 'var(--ok)' : 'var(--err)' }}>
              {ov.snapshot_integrity.ok ? 'OK' : 'MISMATCH'}</div></Link>
        </div>
        <div className="card">
          <div className="label">Environment</div>
          <p>backend v{ov.version} · python {ov.python} · {ov.os} · node {ov.node ?? 'not detected'}</p>
          <div className="label">Not implemented / unavailable</div>
          <ul>{ov.not_implemented.map(n => <li key={n} className="muted">{n}</li>)}</ul>
          <div className="label">Last test run (from this app)</div>
          <p className="mono">{ov.last_test_run ?? 'No test run recorded yet — use Test Center.'}</p>
        </div>
        <div className="card">
          <div className="row"><div className="label" style={{ flex: 1 }}>Recent activity</div><Link to="/console">open console →</Link></div>
          {ov.recent_events.length === 0 ? <div className="empty">No events yet.</div> :
            <table className="data"><tbody>
              {ov.recent_events.slice(0, 10).map(e => (
                <tr key={e.id}><td className="mono">{e.ts}</td><td><Badge s={e.level} /></td>
                  <td>{e.run_id ? <Link to={`/runs/${e.run_id}`}>{e.run_id}</Link> : '—'}</td>
                  <td>{e.message}</td></tr>))}
            </tbody></table>}
        </div>
      </>)}
    </State>
  );
}
