import { useEffect, useState } from 'react';
import { User, KeyRound, Save } from 'lucide-react';
import { changePassword, fetchCurrentUser, updateCurrentUser } from '../lib/api';
import { UserProfile } from '../types';

export default function ProfilePage() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const me = await fetchCurrentUser();
        setProfile(me);
        setEmail(me.email || '');
        setFullName(me.full_name || '');
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to load profile');
      }
    };
    load();
  }, []);

  const handleProfileSave = async () => {
    setSavingProfile(true);
    setError('');
    setMessage('');
    try {
      const updated = await updateCurrentUser({ email, full_name: fullName });
      setProfile(updated);
      setMessage('Profile updated successfully.');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update profile');
    } finally {
      setSavingProfile(false);
    }
  };

  const handlePasswordChange = async () => {
    setSavingPassword(true);
    setError('');
    setMessage('');
    try {
      await changePassword({ current_password: currentPassword, new_password: newPassword });
      setCurrentPassword('');
      setNewPassword('');
      setMessage('Password changed successfully.');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to change password');
    } finally {
      setSavingPassword(false);
    }
  };

  return (
    <div className="nids-page max-w-4xl">
      <h1 className="nids-title">User Profile</h1>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-300 px-4 py-3 rounded-xl">{error}</div>
      )}
      {message && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-xl">{message}</div>
      )}

      <div className="nids-card p-6 space-y-4">
        <div className="flex items-center gap-3 mb-2">
          <User className="w-6 h-6 text-cyan-400" />
          <h2 className="text-xl font-semibold text-slate-100">Account Details</h2>
        </div>

        <div>
          <label className="nids-label">Username</label>
          <input
            value={profile?.username || ''}
            disabled
            className="nids-input bg-slate-800 text-slate-400"
          />
        </div>

        <div>
          <label className="nids-label">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="nids-input"
          />
        </div>

        <div>
          <label className="nids-label">Full Name</label>
          <input
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            className="nids-input"
          />
        </div>

        <button
          onClick={handleProfileSave}
          disabled={savingProfile}
          className="nids-btn-primary"
        >
          <Save className="w-4 h-4" />
          {savingProfile ? 'Saving...' : 'Save Profile'}
        </button>
      </div>

      <div className="nids-card p-6 space-y-4">
        <div className="flex items-center gap-3 mb-2">
          <KeyRound className="w-6 h-6 text-violet-400" />
          <h2 className="text-xl font-semibold text-slate-100">Change Password</h2>
        </div>

        <div>
          <label className="nids-label">Current Password</label>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="nids-input"
          />
        </div>

        <div>
          <label className="nids-label">New Password</label>
          <input
            type="password"
            minLength={8}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="nids-input"
          />
        </div>

        <button
          onClick={handlePasswordChange}
          disabled={savingPassword}
          className="nids-btn-secondary"
        >
          <KeyRound className="w-4 h-4" />
          {savingPassword ? 'Updating...' : 'Update Password'}
        </button>
      </div>
    </div>
  );
}
