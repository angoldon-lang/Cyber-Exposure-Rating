import { useState, type FormEvent } from 'react';
import { ApiError, api, auth } from '../api/client';
import type { UserProfile } from '../api/types';
import { Banner } from '../components/ui';

export default function Login({ onLogin }: { onLogin: (profile: UserProfile) => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.login(email, password);
      auth.set(result.access_token);
      onLogin(result.profile);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : 'Accesso non riuscito');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <div className="card login__card">
        <h1 style={{ fontSize: 20, margin: '0 0 2px' }}>Defenix Exposure Rating</h1>
        <p className="muted small" style={{ marginTop: 0 }}>
          Valutazione dell’esposizione cyber osservabile dall’esterno
        </p>
        {error && <Banner kind="danger">{error}</Banner>}
        <form onSubmit={submit}>
          <label className="login__field">
            <span>Indirizzo e-mail</span>
            <input type="email" value={email} autoComplete="username" required
                   onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="login__field">
            <span>Password</span>
            <input type="password" value={password} autoComplete="current-password" required
                   onChange={(e) => setPassword(e.target.value)} />
          </label>
          <button className="btn" type="submit" disabled={busy} style={{ width: '100%' }}>
            {busy ? 'Accesso in corso…' : 'Accedi'}
          </button>
        </form>
        <p className="muted small" style={{ marginTop: 14, marginBottom: 0 }}>
          In produzione l’autenticazione e’ delegata all’identity provider OIDC
          (Keycloak) con MFA. L’accesso locale e’ previsto solo per sviluppo e
          installazioni minime.
        </p>
      </div>
    </div>
  );
}
