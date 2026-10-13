import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { State, useAsync, Json } from '../components/ui';

export default function WalletLab() {
  const [q, setQ] = useState('');
  const [kind, setKind] = useState('');
  const { data: rows, error, loading, reload } = useAsync(() => api.samples(q || undefined, kind || undefined), [q, kind]);
  const mods = useAsync(api.modules, []);
  const [label, setLabel] = useState('');
  const [k, setK] = useState('seeded-buffer');
  const [params, setParams] = useState('{\n  "seed": 42,\n  "length": 32\n}');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [created, setCreated] = useState<Record<string, unknown> | null>(null);

  async function create() {
    setBusy(true); setMsg(null); setCreated(null);
    try {
      const p = JSON.parse(params);
      const s = await api.createSample({ label, kind: k, params: p });
      setCreated(s as unknown as Record<string, unknown>);
      setMsg(`Sample ${s.id} created (real operation result below).`);
      reload();
    } catch (e) { setMsg(String((e as Error).message)); }
    finally { setBusy(false); }
  }

  return (
    <>
      <div className="warnbox">Synthetic research samples only. This module does not create real wallets, does not handle mnemonics/private keys, and makes no unverified Trust Wallet compatibility claims.</div>
      <div className="card">
        <div className="label">Create test sample</div>
        <div className="row" style={{ marginTop: 8 }}>
          <input placeholder="label" value={label} onChange={e => setLabel(e.target.value)} />
          <select value={k} onChange={e => setK(e.target.value)}>
            {(mods.data?.sample_kinds ?? []).map(x => <option key={x} value={x}>{x}</option>)}
          </select>
          <button onClick={create} disabled={busy || !label}>{busy ? 'running…' : 'create'}</button>
        </div>
        <textarea rows={5} cols={60} value={params} onChange={e => setParams(e.target.value)} style={{ marginTop: 8, fontFamily: 'var(--mono)', width: '100%' }} />
        {msg && <p className="muted">{msg}</p>}
        {created && <Json v={created} max={1500} />}
      </div>
      <div className="card">
        <div className="row">
          <div className="label" style={{ flex: 1 }}>Samples</div>
          <input placeholder="search" value={q} onChange={e => setQ(e.target.value)} />
          <select value={kind} onChange={e => setKind(e.target.value)}>
            <option value="">all kinds</option>
            {(mods.data?.sample_kinds ?? []).map(x => <option key={x} value={x}>{x}</option>)}
          </select>
          <a href="/api/wallet-lab/samples?fmt=csv" className="badge info">export CSV</a>
        </div>
        <State loading={loading} error={error} empty={!rows || rows.length === 0}>
          {rows && rows.length > 0 && (
            <table className="data">
              <thead><tr><th>id</th><th>label</th><th>kind</th><th>created</th><th>validation</th></tr></thead>
              <tbody>{rows.map(s => (
                <tr key={s.id}><td className="mono"><Link to={`/wallet-lab/${s.id}`}>{s.id}</Link></td>
                  <td>{s.label}</td><td>{s.kind}</td><td className="mono">{s.created_at}</td>
                  <td className="muted">{JSON.stringify(s.validation)}</td></tr>))}
              </tbody>
            </table>)}
        </State>
      </div>
    </>
  );
}
