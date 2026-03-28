import { useState } from 'react';
import { Shield } from 'lucide-react';
import { login, register } from '../lib/api';

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (mode === 'register') {
        await register({
          username,
          email,
          password,
          full_name: fullName || undefined,
        });
      }
      await login(username, password);
      onLogin();
    } catch (err: any) {
      setError(err.response?.data?.detail || `${mode === 'login' ? 'Login' : 'Registration'} failed`);
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
                onClick={() => setMode('login')}
                className={`flex-1 py-2 text-sm rounded-lg ${mode === 'login' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-300'}`}
              >
                Login
              </button>
              <button
                type="button"
                onClick={() => setMode('register')}
                className={`flex-1 py-2 text-sm rounded-lg ${mode === 'register' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-300'}`}
              >
                Register
              </button>
            </div>

            <div>
              <label htmlFor="username" className="nids-label">
                Username or Email
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="nids-input"
                placeholder="Enter username or email"
                required
              />
            </div>

            {mode === 'register' && (
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
              </>
            )}

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
            </div>

            {error && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-3 text-rose-300 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="nids-btn-primary w-full"
            >
              {loading ? (mode === 'login' ? 'Logging in...' : 'Creating account...') : (mode === 'login' ? 'Log In' : 'Create Account')}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-slate-500">
            Default admin: admin / admin
          </div>
        </div>
      </div>
    </div>
  );
}
