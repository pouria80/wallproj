import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Wallets from './pages/Wallets.jsx'
import Recovery from './pages/Recovery.jsx'
import EngineInfo from './pages/EngineInfo.jsx'
import './styles.css'

export default function App() {
  return (
    <HashRouter>
      <div className="shell">
        <header className="topbar">
          <div className="brand">🧪 WalletLab <span>سندباکس تحقیقاتی CVE-2023-31290</span></div>
          <nav>
            <NavLink to="/">داشبورد</NavLink>
            <NavLink to="/wallets">کیف‌پول‌ها</NavLink>
            <NavLink to="/recovery">بازیابی</NavLink>
            <NavLink to="/engine">موتور و محدودیت‌ها</NavLink>
          </nav>
        </header>
        <div className="banner">
          ⚠️ داده‌ها کاملاً <b>مصنوعی و محلی</b> هستند: موجودی‌ها شبیه‌سازی‌شده، آدرس‌ها placeholder شیمیایی. هیچ اتصال شبکه‌ای به زنجیره واقعی وجود ندارد.
        </div>
        <main>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/wallets" element={<Wallets />} />
            <Route path="/recovery" element={<Recovery />} />
            <Route path="/engine" element={<EngineInfo />} />
          </Routes>
        </main>
        <footer>WalletLab — ساخته‌شده روی هسته تحقیقاتی rng_research (MT19937 راستی‌آزمایی‌شده با اوراکل g++)</footer>
      </div>
    </HashRouter>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode><App /></React.StrictMode>
)
