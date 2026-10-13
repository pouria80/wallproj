import { useParams, Link } from 'react-router-dom';
import { api } from '../api';
import { State, useAsync, Json } from '../components/ui';

export default function SampleDetail() {
  const { sid } = useParams();
  const { data: s, error, loading } = useAsync(() => api.sample(sid!), [sid]);
  return (
    <State loading={loading} error={error}>
      {s && <div className="card">
        <h3>{s.label} <span className="muted mono">({s.id})</span></h3>
        <p><b>Type/format:</b> {s.kind} &nbsp; <b>Created:</b> <span className="mono">{s.created_at}</span></p>
        <div className="label">Registered parameters</div><Json v={s.params} max={1200} />
        <div className="label">Metadata (generation method / tool version)</div><Json v={s.metadata} max={1200} />
        <div className="label">Structural validation</div><Json v={s.validation} max={1200} />
        <div className="label">Operation history</div>
        <ul>{(s.ops ?? []).map((o, i) => <li key={i} className="mono">{o.ts} — {o.op} {o.detail}</li>)}</ul>
        <div className="warnbox">{(s as { interpretation_limit?: string }).interpretation_limit}</div>
        <Link to="/wallet-lab">← back to Wallet Lab</Link>
      </div>}
    </State>
  );
}
