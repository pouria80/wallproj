import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { State, useAsync, Json, Badge } from '../components/ui';

const DEFAULT_PARAMS: Record<string, string> = {
  'mt19937-reference': '{ "seed": 42 }',
  'vulnerable-model': '{ "seeds": [7, 7], "length": 16 }',
  'secure-rng': '{ "n": 32 }',
};

export default function RngResearch() {
  const mods = useAsync(api.modules, []);
  const runs = useAsync(api.runs, []);
  const [probeId, setProbeId] = useState('mt19937-reference');
  const [probeParams, setProbeParams] = useState(DEFAULT_PARAMS['mt19937-reference']);
  const [probeOut, setProbeOut] = useState<Record<string, unknown> | null>(null);
  const [probeErr, setProbeErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [expId, setExpId] = useState('E1-source-snapshot-analysis');
  const [expParams, setExpParams] = useState('{}');
  const [launchMsg, setLaunchMsg] = useState<string | null>(null);

  async function probe() {
    setBusy(true); setProbeErr(null); setProbeOut(null);
    try {
      setProbeOut(await api.probeModel(probeId, JSON.parse(probeParams)));
    } catch (e) { setProbeErr(String((e as Error).message)); }
    finally { setBusy(false); }
  }
  async function launch() {
    setLaunchMsg(null);
    try {
      const r = await api.startRun(expId, JSON.parse(expParams));
      setLaunchMsg(`Queued run ${r.run_id} — opening…`);
      setTimeout(() => { window.location.href = `/runs/${r.run_id}`; }, 500);
    } catch (e) { setLaunchMsg('Error: ' + String((e as Error).message)); }
  }

  return (
    <State loading={mods.loading} error={mods.error}>
      {mods.data && (<>
        <div className="card">
          <div className="label">RNG models implemented in the research core</div>
          {Object.entries(mods.data.models).map(([id, m]) => (
            <div key={id} style={{ borderBottom: '1px solid var(--border)', padding: '10px 0' }}>
              <b>{id}</b>{' '}
              <span className="muted">{String(m.status)}</span>
              <table className="data"><tbody>
                {(['purpose', 'origin', 'inputs', 'params', 'output', 'validation',
                   'limitations', 'tests'] as const).map(k => (
                  <tr key={k}><td className="label" style={{ width: 130 }}>{k}</td>
                    <td>{Array.isArray(m[k]) ? (m[k] as string[]).join(', ') : String(m[k] ?? '')}</td></tr>))}
              </tbody></table>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="label">Deterministic model probe (real computation)</div>
          <div className="row" style={{ marginTop: 8 }}>
            <select value={probeId} onChange={e => { setProbeId(e.target.value); setProbeParams(DEFAULT_PARAMS[e.target.value] ?? '{}'); }}>
              {Object.keys(mods.data.models).map(id => <option key={id} value={id}>{id}</option>)}
            </select>
            <input value={probeParams} onChange={e => setProbeParams(e.target.value)} style={{ fontFamily: 'var(--mono)', flex: 1, minWidth: 220 }} />
            <button onClick={probe} disabled={busy}>{busy ? 'computing…' : 'run probe'}</button>
          </div>
          {probeErr && <div className="errbox">{probeErr}</div>}
          {probeOut && <Json v={probeOut} max={2500} />}
        </div>

        <div className="card">
          <div className="label">Runnable core experiments (registry E1–E5)</div>
          <table className="data">
            <thead><tr><th>id</th><th>category</th><th>description</th></tr></thead>
            <tbody>{Object.entries(mods.data.core_experiments).map(([id, e]) => (
              <tr key={id}><td className="mono">{id}</td><td>{e.category}</td><td className="muted">{e.description}</td></tr>))}
            </tbody>
          </table>
          <div className="row" style={{ marginTop: 10 }}>
            <select value={expId} onChange={e => setExpId(e.target.value)}>
              {Object.keys(mods.data.core_experiments).map(id => <option key={id} value={id}>{id}</option>)}
            </select>
            <input value={expParams} onChange={e => setExpParams(e.target.value)} placeholder='{"param": ...}' style={{ fontFamily: 'var(--mono)', flex: 1, minWidth: 200 }} />
            <button onClick={launch}>start experiment</button>
          </div>
          {launchMsg && <p className="muted">{launchMsg}</p>}
        </div>

        <div className="card">
          <div className="row"><div className="label" style={{ flex: 1 }}>Recent runs</div><Link to="/runs">all runs →</Link></div>
          {!runs.data || runs.data.length === 0 ? <div className="empty">No runs recorded yet.</div> : (
            <table className="data"><tbody>
              {runs.data.slice(0, 8).map(r => (
                <tr key={r.id}><td className="mono"><Link to={`/runs/${r.id}`}>{r.id}</Link></td>
                  <td>{r.experiment_id}</td><td><Badge s={r.status} /></td>
                  <td className="mono muted">{r.created_at}</td></tr>))}
            </tbody></table>)}
        </div>
      </>)}
    </State>
  );
}
