import { useState } from 'react';
import { Shield } from 'lucide-react';
import { confirmPasswordReset, login, register, requestPasswordReset } from '../lib/api';

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [mode, setMode] = useState<'login' | 'register' | 'forgot' | 'reset'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      if (mode === 'login') {
        await login(username, password);
        onLogin();
      } else if (mode === 'register') {
        // Note: Registration requires admin privileges. 
        // For self-registration, contact your administrator.
        await register({
          username,
          email,
          password,
          full_name: fullName || undefined,
        });
        setSuccess('Account created! You can now log in.');
        setMode('login');
      } else if (mode === 'forgot') {
        await requestPasswordReset(email);
        setSuccess('If this email exists, a reset token has been sent. Check your email.');
        setMode('reset');
      } else if (mode === 'reset') {
        await confirmPasswordReset({ email, token: resetToken, new_password: newPassword });
        setSuccess('Password reset successful! You can now log in with your new password.');
        setMode('login');
        setPassword('');
        setResetToken('');
        setNewPassword('');
      }
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      if (mode === 'register' && detail === 'Not authenticated') {
        setError('Registration requires admin approval. Please contact your administrator.');
      } else {
        setError(
          detail ||
            (mode === 'login' ? 'Login failed' : mode === 'register' ? 'Registration failed' : 'Request failed')
        );
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-cyan-500 rounded-2xl mb-4 shadow-lg shadow-cyan-500/20">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white">NIDS Dashboard</h1>
          <p className="text-slate-400 mt-2">Security Operations Console</p>
        </div>

        <div className="nids-card p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex bg-slate-800 rounded-xl p-1">
              <button
                type="button"
                onClick={() => { setMode('login'); setError(''); setSuccess(''); }}
                className={`flex-1 py-2 text-sm rounded-lg ${mode === 'login' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-300'}`}
              >
                Login
              </button>
              <button
                type="button"
                onClick={() => { setMode('register'); setError(''); setSuccess(''); }}
                className={`flex-1 py-2 text-sm rounded-lg ${mode === 'register' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-300'}`}
              >
                Register
              </button>
            </div>

            {mode === 'register' && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3 text-amber-200 text-sm">
                <p className="font-medium">⚠️ Admin-Only Feature</p>
                <p className="mt-1">New user registration requires admin privileges. Click <button type="button" onClick={() => setMode('login')} className="underline text-cyan-300 hover:text-cyan-200">Login</button> and sign in as admin first (admin / admin).</p>
              </div>
            )}

            <div>
              <label htmlFor="username" className="nids-label">
                {mode === 'login' ? 'Username or Email' : 'Username'}
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="nids-input"
                placeholder={mode === 'login' ? 'Enter username or email' : 'Enter username'}
                required={mode === 'login' || mode === 'register'}
                disabled={mode === 'forgot' || mode === 'reset'}
              />
            </div>

            {(mode === 'register' || mode === 'forgot' || mode === 'reset') && (
              <>
                <div>
                  <label htmlFor="email" className="nids-label">
                    Email
                  </label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="nids-input"
                    placeholder="you@example.com"
                    required
                  />
                </div>

                {mode === 'register' && (
                  <div>
                    <label htmlFor="full-name" className="nids-label">
                      Full Name (optional)
                    </label>
                    <input
                      id="full-name"
                      type="text"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      className="nids-input"
                      placeholder="Your name"
                    />
                  </div>
                )}
              </>
            )}

            {(mode === 'login' || mode === 'register') && (
              <div>
                <label htmlFor="password" className="nids-label">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="nids-input"
                  placeholder="Enter password"
                  minLength={8}
                  required
                />
                {mode === 'login' && (
                  <div className="mt-3">
                    <button
                      type="button"
                      onClick={() => setMode('forgot')}
                      className="w-full rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-200 hover:bg-cyan-500/20"
                    >
                      Forgot password? Reset with email token
                    </button>
                  </div>
                )}
              </div>
            )}

            {mode === 'reset' && (
              <>
                <div>
                  <label htmlFor="reset-token" className="nids-label">
                    Reset Token
                  </label>
                  <input
                    id="reset-token"
                    type="text"
                    value={resetToken}
                    onChange={(e) => setResetToken(e.target.value)}
                    className="nids-input"
                    placeholder="Paste token from email"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="new-password" className="nids-label">
                    New Password
                  </label>
                  <input
                    id="new-password"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="nids-input"
                    placeholder="Enter new password"
                    minLength={8}
                    required
                  />
                </div>
              </>
            )}

            {error && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-3 text-rose-300 text-sm">
                {error}
              </div>
            )}

            {success && (
              <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-3 text-emerald-300 text-sm">
                {success}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="nids-btn-primary w-full"
            >
              {loading
                ? mode === 'login'
                  ? 'Logging in...'
                  : mode === 'register'
                    ? 'Creating account...'
                    : mode === 'forgot'
                      ? 'Sending reset token...'
                      : 'Resetting password...'
                : mode === 'login'
                  ? 'Log In'
                  : mode === 'register'
                    ? 'Create Account'
                    : mode === 'forgot'
                      ? 'Send Reset Token'
                      : 'Reset Password'}
            </button>
          </form>

          <div className="mt-4 text-center text-sm">
            {(mode === 'forgot' || mode === 'reset') && (
              <button type="button" onClick={() => setMode('login')} className="text-cyan-300 hover:text-cyan-200">
                Back to login
              </button>
            )}
          </div>

          <div className="mt-2 text-center text-sm text-slate-500">Default admin: admin / admin</div>
        </div>
      </div>
    </div>
  );
}
