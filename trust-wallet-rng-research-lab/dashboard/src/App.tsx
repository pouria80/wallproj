import { useEffect, useState } from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'
import { api } from './api'
import Overview from './pages/Overview'
import WalletLab from './pages/WalletLab'
import SampleDetail from './pages/SampleDetail'
import RngResearch from './pages/RngResearch'
import ExperimentBuilder from './pages/ExperimentBuilder'
import RunsPage from './pages/RunsPage'
import RunDetail from './pages/RunDetail'
import EvidenceExplorer from './pages/EvidenceExplorer'
import FindingsPage from './pages/Findings'
import ComparisonLab from './pages/ComparisonLab'
import Reports from './pages/Reports'
import Console from './pages/Console'
import TestCenter from './pages/TestCenter'
import SettingsPage from './pages/Settings'

const NAV = [
  ['/', 'Overview'], ['/wallet-lab', 'Wallet Lab'], ['/rng-research', 'RNG Research'],
  ['/experiments', 'Experiment Builder'], ['/runs', 'Runs'], ['/evidence', 'Evidence Explorer'],
  ['/findings', 'Findings'], ['/compare', 'Comparison Lab'], ['/reports', 'Reports'],
  ['/console', 'Execution Console'], ['/tests', 'Test Center'], ['/settings', 'Settings'],
] as const;

export default function App() {
  const [health, setHealth] = useState<string>('checking');
  const [q, setQ] = useState('');
  useEffect(() => {
    let alive = true;
    const ping = () => api.health()
      .then(h => alive && setHealth(h.status === 'ok' ? (h.snapshot_integrity ? 'online · evidence OK' : 'online · EVIDENCE WARNING') : 'degraded'))
      .catch(() => alive && setHealth('offline'));
    ping();
    const t = setInterval(ping, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>RNG Research Lab</h1>
        <nav>
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === '/'}>{label}</NavLink>
          ))}
        </nav>
      </aside>
      <main className="main">
        <div className="topbar">
          <span className={`badge ${health.startsWith('online') ? 'ok' : health === 'degraded' ? 'warning' : 'error'}`}>
            backend: {health}
          </span>
          <input placeholder="jump to run id…" value={q} onChange={e => setQ(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && /^R-/.test(q.trim())) window.location.href = `/runs/${q.trim()}`; }}
            style={{ marginLeft: 'auto', width: 220 }} />
        </div>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/wallet-lab" element={<WalletLab />} />
          <Route path="/wallet-lab/:sid" element={<SampleDetail />} />
          <Route path="/rng-research" element={<RngResearch />} />
          <Route path="/experiments" element={<ExperimentBuilder />} />
          <Route path="/runs" element={<RunsPage />} />
          <Route path="/runs/:rid" element={<RunDetail />} />
          <Route path="/evidence" element={<EvidenceExplorer />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/compare" element={<ComparisonLab />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/console" element={<Console />} />
          <Route path="/tests" element={<TestCenter />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<div className="empty">Not found</div>} />
        </Routes>
      </main>
    </div>
  );
}
