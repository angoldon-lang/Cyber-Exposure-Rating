import { useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { api, auth } from './api/client';
import type { Company, UserProfile } from './api/types';
import CompanyDashboard from './pages/CompanyDashboard';
import CompanyManage from './pages/CompanyManage';
import Findings from './pages/Findings';
import Login from './pages/Login';
import Portfolio from './pages/Portfolio';
import Remediation from './pages/Remediation';
import Reports from './pages/Reports';
import Scans from './pages/Scans';
import { Spinner } from './components/ui';

function CompanyNav({ companies }: { companies: Company[] }) {
  const { companyId } = useParams();
  return (
    <nav aria-label="Aziende">
      {companies.map((company) => (
        <NavLink key={company.id} to={`/aziende/${company.id}`}
                 className={companyId === company.id ? 'active' : undefined}>
          {company.legal_name}
        </NavLink>
      ))}
    </nav>
  );
}

function Shell({ profile, companies, onLogout }:
  { profile: UserProfile; companies: Company[]; onLogout: () => void }) {
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar__brand">
          Defenix
          <span>Exposure Rating</span>
        </div>

        <nav aria-label="Navigazione principale">
          <NavLink to="/portfolio" className={({ isActive }) => (isActive ? 'active' : undefined)}>
            Portfolio
          </NavLink>
          <NavLink to="/aziende/nuova/gestione"
                   className={({ isActive }) => (isActive ? 'active' : undefined)}>
            Nuova azienda
          </NavLink>
        </nav>

        <div>
          <div style={{ fontSize: 11, opacity: .7, textTransform: 'uppercase',
                        letterSpacing: '.4px', marginBottom: 6 }}>
            Aziende
          </div>
          <Routes>
            <Route path="/aziende/:companyId/*" element={<CompanyNav companies={companies} />} />
            <Route path="*" element={<CompanyNav companies={companies} />} />
          </Routes>
        </div>

        <div className="sidebar__foot">
          <div style={{ marginBottom: 6 }}>
            {profile.full_name ?? profile.email}
            <br />
            <span style={{ opacity: .8 }}>{profile.roles.join(', ')}</span>
          </div>
          <button className="btn btn--ghost" onClick={onLogout}
                  style={{ color: '#fff', borderColor: 'rgba(255,255,255,.3)', padding: '4px 10px',
                           fontSize: 12 }}>
            Esci
          </button>
          <p style={{ marginTop: 12, marginBottom: 0 }}>
            Valutazione dell’esposizione osservabile dall’esterno. Non e’ un
            penetration test ne’ una certificazione di sicurezza.
          </p>
        </div>
      </aside>

      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/portfolio" replace />} />
          <Route path="/portfolio" element={<Portfolio />} />
          <Route path="/aziende/:companyId" element={<CompanyDashboard />} />
          <Route path="/aziende/:companyId/gestione" element={<CompanyManage />} />
          <Route path="/aziende/:companyId/scansioni" element={<Scans />} />
          <Route path="/scansioni/:scanId/rilievi" element={<Findings />} />
          <Route path="/scansioni/:scanId/remediation" element={<Remediation />} />
          <Route path="/scansioni/:scanId/report" element={<Reports />} />
          <Route path="*" element={<p className="muted">Pagina non trovata.</p>} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [companies, setCompanies] = useState<Company[]>([]);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    if (!auth.token) { setChecking(false); return; }
    api.me()
      .then(setProfile)
      .catch(() => auth.clear())
      .finally(() => setChecking(false));
  }, []);

  // L'elenco viene riletto a ogni cambio di pagina: creando, archiviando o
  // cancellando un'azienda si passa sempre per una navigazione, quindi la barra
  // laterale resta allineata senza bisogno di ricaricare a mano.
  const { pathname } = useLocation();
  useEffect(() => {
    if (!profile) return;
    api.companies().then((page) => setCompanies(page.items)).catch(() => setCompanies([]));
  }, [profile, pathname]);

  if (checking) return <div className="login"><Spinner /></div>;
  if (!profile) return <Login onLogin={setProfile} />;

  return <Shell profile={profile} companies={companies}
                onLogout={() => { auth.clear(); setProfile(null); }} />;
}
