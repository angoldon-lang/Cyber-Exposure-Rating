import { useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { api, auth } from './api/client';
import type { Company, UserProfile } from './api/types';
import Assets from './pages/Assets';
import CompanyDashboard from './pages/CompanyDashboard';
import BrandingPage from './pages/Branding';
import CompanyManage from './pages/CompanyManage';
import Findings from './pages/Findings';
import Login from './pages/Login';
import Portfolio from './pages/Portfolio';
import Remediation from './pages/Remediation';
import Reports from './pages/Reports';
import Scans from './pages/Scans';
import { Spinner } from './components/ui';

/** Sezioni sempre raggiungibili per l'azienda selezionata.
 *
 *  Prima erano linkate solo dalla dashboard, e solo quando esisteva gia' una
 *  scansione completata: con una scansione in coda la sezione Scansioni era
 *  irraggiungibile, proprio quando serviva per seguirne l'avanzamento. */
function SezioniAzienda({ companyId }: { companyId: string }) {
  const voci = [
    { to: `/aziende/${companyId}`, etichetta: 'Dashboard', end: true },
    { to: `/aziende/${companyId}/scansioni`, etichetta: 'Scansioni', end: false },
    { to: `/aziende/${companyId}/asset`, etichetta: 'Asset', end: false },
    { to: `/aziende/${companyId}/gestione`, etichetta: 'Gestione', end: false },
  ];
  return (
    <div className="subnav">
      {voci.map((voce) => (
        <NavLink key={voce.to} to={voce.to} end={voce.end}
                 className={({ isActive }) => (isActive ? 'active' : undefined)}>
          {voce.etichetta}
        </NavLink>
      ))}
    </div>
  );
}

function CompanyNav({ companies }: { companies: Company[] }) {
  const { companyId } = useParams();
  return (
    <nav aria-label="Aziende">
      {companies.map((company) => (
        <div key={company.id}>
          <NavLink to={`/aziende/${company.id}`}
                   className={companyId === company.id ? 'active' : undefined}>
            {company.legal_name}
          </NavLink>
          {companyId === company.id && <SezioniAzienda companyId={company.id} />}
        </div>
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
          <NavLink to="/personalizzazione"
                   className={({ isActive }) => (isActive ? 'active' : undefined)}>
            Personalizzazione
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
          <Route path="/personalizzazione" element={<BrandingPage />} />
          <Route path="/aziende/:companyId/scansioni" element={<Scans />} />
          <Route path="/aziende/:companyId/asset" element={<Assets />} />
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
