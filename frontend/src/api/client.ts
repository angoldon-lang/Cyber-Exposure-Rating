/** Client HTTP tipizzato verso l'API Defenix. */
import type {
  Authorization, AuthorizationPreview, Branding, Company, CompanyInput, DashboardOverview,
  Domain,
  Finding, Health, IPAddressEntry, NetworkRangeEntry, Page, PortfolioView, PurgeResult,
  RemediationItem, Report, Scan, ScanComparison,
  ScanDetail, ScanProfile, ScopeEntry, ScopeEntryInput, ScoreDetail, TokenResponse,
  UserProfile, VerificationChallenge, VerificationResult,
} from './types';

const BASE = '/api/v1';
const TOKEN_KEY = 'defenix.token';

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) {
    super(message);
    this.name = 'ApiError';
  }
}

export const auth = {
  get token(): string | null {
    try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  set(token: string) {
    try { localStorage.setItem(TOKEN_KEY, token); } catch { /* storage non disponibile */ }
  },
  clear() {
    try { localStorage.removeItem(TOKEN_KEY); } catch { /* storage non disponibile */ }
  },
};

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body) headers.set('Content-Type', 'application/json');
  const token = auth.token;
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(`${BASE}${path}`, { ...init, headers });
  if (response.status === 401) {
    auth.clear();
    throw new ApiError(401, 'Sessione scaduta: e’ necessario autenticarsi di nuovo');
  }
  if (!response.ok) {
    let message = `Errore ${response.status}`;
    let detail: unknown;
    try {
      const payload = await response.json();
      detail = payload?.detail ?? payload;
      if (typeof payload?.detail === 'string') message = payload.detail;
      else if (typeof payload?.error === 'string') message = payload.error;
      else if (typeof payload?.detail?.error === 'string') message = payload.detail.error;
    } catch { /* corpo non JSON */ }
    throw new ApiError(response.status, message, detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  login: (email: string, password: string) =>
    request<TokenResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  me: () => request<UserProfile>('/auth/me'),

  health: () => request<Health>('/health'),
  disclaimer: () => request<{ it: string; en: string }>('/meta/disclaimer'),
  profiles: () => request<Record<string, {
    label_it: string; description_it: string; requires_verification: boolean;
    requires_authorization: boolean; tools: string[]; forbidden_actions: string[];
  }>>('/meta/profiles'),
  branding: () => request<Branding>('/branding'),
  updateBranding: (body: Partial<Branding>) =>
    request<Branding>('/branding', { method: 'PUT', body: JSON.stringify(body) }),
  deleteLogo: () => request<void>('/branding/logo', { method: 'DELETE' }),
  logoUrl: () => `${BASE}/branding/logo`,
  /** Il logo si carica come multipart: non si imposta Content-Type a mano,
   *  ci pensa il browser aggiungendo il boundary. */
  uploadLogo: async (file: File): Promise<Branding> => {
    const dati = new FormData();
    dati.append('file', file);
    const headers = new Headers();
    const token = auth.token;
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const risposta = await fetch(`${BASE}/branding/logo`, { method: 'POST', body: dati, headers });
    if (!risposta.ok) {
      let messaggio = `Errore ${risposta.status}`;
      try {
        const corpo = await risposta.json();
        if (typeof corpo?.detail === 'string') messaggio = corpo.detail;
      } catch { /* corpo non JSON */ }
      throw new ApiError(risposta.status, messaggio);
    }
    return (await risposta.json()) as Branding;
  },

  scoringModel: () => request<Record<string, unknown>>('/meta/scoring-model'),

  companies: (search?: string) =>
    request<Page<Company>>(`/companies${search ? `?search=${encodeURIComponent(search)}` : ''}`),
  company: (id: string) => request<Company>(`/companies/${id}`),

  // --- gestione anagrafica -------------------------------------------------
  createCompany: (body: CompanyInput) =>
    request<Company>('/companies', { method: 'POST', body: JSON.stringify(body) }),
  updateCompany: (id: string, body: Partial<CompanyInput> & { is_active?: boolean }) =>
    request<Company>(`/companies/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  /** Archivia: l'azienda esce dagli elenchi operativi, lo storico resta. */
  archiveCompany: (id: string) => request<void>(`/companies/${id}`, { method: 'DELETE' }),
  /** Cancellazione definitiva e irreversibile: richiede di ridigitare lo slug. */
  purgeCompany: (id: string, body: { confirm_slug: string; reason: string }) =>
    request<PurgeResult>(`/companies/${id}/purge`, { method: 'POST', body: JSON.stringify(body) }),

  // --- domini e verifica ---------------------------------------------------
  domains: (companyId: string) => request<Domain[]>(`/companies/${companyId}/domains`),
  addDomain: (companyId: string, body: { name: string; is_primary?: boolean }) =>
    request<Domain>(`/companies/${companyId}/domains`, { method: 'POST', body: JSON.stringify(body) }),
  deleteDomain: (companyId: string, domainId: string) =>
    request<void>(`/companies/${companyId}/domains/${domainId}`, { method: 'DELETE' }),
  startVerification: (companyId: string, domainId: string, method: string) =>
    request<VerificationChallenge>(`/companies/${companyId}/domains/${domainId}/verification`,
      { method: 'POST', body: JSON.stringify({ method }) }),
  checkVerification: (companyId: string, domainId: string, method: string) =>
    request<VerificationResult>(`/companies/${companyId}/domains/${domainId}/verification/check`,
      { method: 'POST', body: JSON.stringify({ method }) }),
  approveDomain: (companyId: string, domainId: string,
                  body: { approver_name: string; document_reference: string; notes?: string }) =>
    request<VerificationResult>(`/companies/${companyId}/domains/${domainId}/verification/approve`,
      { method: 'POST', body: JSON.stringify(body) }),

  // --- autorizzazioni e perimetro -----------------------------------------
  authorizations: (companyId: string) =>
    request<Authorization[]>(`/companies/${companyId}/authorizations`),
  createAuthorization: (companyId: string, body: Record<string, unknown>) =>
    request<Authorization>(`/companies/${companyId}/authorizations`,
      { method: 'POST', body: JSON.stringify(body) }),
  revokeAuthorization: (companyId: string, authorizationId: string, reason: string) =>
    request<Authorization>(`/companies/${companyId}/authorizations/${authorizationId}/revoke`,
      { method: 'POST', body: JSON.stringify({ reason }) }),
  scopes: (companyId: string) => request<ScopeEntry[]>(`/companies/${companyId}/scopes`),
  addScope: (companyId: string, body: ScopeEntryInput) =>
    request<ScopeEntry>(`/companies/${companyId}/scopes`, { method: 'POST', body: JSON.stringify(body) }),
  deleteScope: (companyId: string, scopeId: string) =>
    request<void>(`/companies/${companyId}/scopes/${scopeId}`, { method: 'DELETE' }),

  // --- perimetro di rete ---------------------------------------------------
  ips: (companyId: string) => request<IPAddressEntry[]>(`/companies/${companyId}/ips`),
  addIp: (companyId: string, body: { address: string; authorized?: boolean }) =>
    request<IPAddressEntry>(`/companies/${companyId}/ips`,
      { method: 'POST', body: JSON.stringify(body) }),
  setIpAuthorization: (companyId: string, ipId: string, authorized: boolean) =>
    request<IPAddressEntry>(`/companies/${companyId}/ips/${ipId}/authorization`,
      { method: 'POST', body: JSON.stringify({ authorized }) }),
  deleteIp: (companyId: string, ipId: string) =>
    request<void>(`/companies/${companyId}/ips/${ipId}`, { method: 'DELETE' }),
  networks: (companyId: string) =>
    request<NetworkRangeEntry[]>(`/companies/${companyId}/networks`),
  addNetwork: (companyId: string, body: { cidr: string; description?: string | null }) =>
    request<NetworkRangeEntry>(`/companies/${companyId}/networks`,
      { method: 'POST', body: JSON.stringify(body) }),
  deleteNetwork: (companyId: string, networkId: string) =>
    request<void>(`/companies/${companyId}/networks/${networkId}`, { method: 'DELETE' }),
  dashboard: (id: string) => request<DashboardOverview>(`/companies/${id}/dashboard`),
  portfolio: () => request<PortfolioView>('/portfolio'),

  scans: (companyId: string) => request<Page<Scan>>(`/companies/${companyId}/scans`),
  scan: (scanId: string) => request<ScanDetail>(`/scans/${scanId}`),
  authorizationPreview: (companyId: string, profile: ScanProfile) =>
    request<AuthorizationPreview>(`/companies/${companyId}/scans/authorization-preview?profile=${profile}`),
  startScan: (companyId: string, profile: ScanProfile) =>
    request<Scan>(`/companies/${companyId}/scans`, { method: 'POST', body: JSON.stringify({ profile }) }),

  score: (scanId: string) => request<ScoreDetail>(`/scans/${scanId}/score`),
  findings: (scanId: string, params: Record<string, string> = {}) => {
    const query = new URLSearchParams({ page_size: '300', ...params }).toString();
    return request<Page<Finding>>(`/scans/${scanId}/findings?${query}`);
  },
  reviewFinding: (findingId: string, body: {
    action: string; reason?: string; new_severity?: string; new_confidence?: string;
  }) => request<Finding>(`/findings/${findingId}/review`, { method: 'POST', body: JSON.stringify(body) }),
  remediationPlan: (scanId: string, onlyQuickWins = false) =>
    request<RemediationItem[]>(`/scans/${scanId}/remediation-plan?only_quick_wins=${onlyQuickWins}`),
  comparison: (scanId: string) => request<ScanComparison>(`/scans/${scanId}/comparison`),

  reports: (scanId: string) => request<Report[]>(`/scans/${scanId}/reports`),
  generateReport: (scanId: string, body: {
    report_type?: string; language?: string; formats?: string[]; is_final?: boolean;
  }) => request<Report>(`/scans/${scanId}/reports`, { method: 'POST', body: JSON.stringify(body) }),
  downloadUrl: (reportId: string, format: string) => `${BASE}/reports/${reportId}/download/${format}`,
};

/** Scarica un file autenticato: il token viaggia nell'header, non nell'URL. */
export async function downloadReport(reportId: string, format: string, filename: string): Promise<void> {
  const headers = new Headers();
  const token = auth.token;
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(api.downloadUrl(reportId, format), { headers });
  if (!response.ok) throw new ApiError(response.status, 'Download non riuscito');
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
