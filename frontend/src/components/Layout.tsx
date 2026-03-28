import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Shield, 
  Globe, 
  Brain, 
  ActivitySquare,
  BriefcaseBusiness,
  Workflow,
  User,
  Settings as SettingsIcon,
  LogOut
} from 'lucide-react';
import { logout } from '../lib/api';
import clsx from 'clsx';

interface LayoutProps {
  children: React.ReactNode;
  onLogout: () => void;
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Events', href: '/events', icon: AlertTriangle },
  { name: 'Cases', href: '/cases', icon: BriefcaseBusiness },
  { name: 'Rules', href: '/rules', icon: Shield },
  { name: 'Playbooks', href: '/playbooks', icon: Workflow },
  { name: 'Threat Map', href: '/threat-map', icon: Globe },
  { name: 'ML Monitor', href: '/ml-monitor', icon: Brain },
  { name: 'Platform & Ops', href: '/ops-platform', icon: ActivitySquare },
  { name: 'Profile', href: '/profile', icon: User },
  { name: 'Settings', href: '/settings', icon: SettingsIcon },
];

export default function Layout({ children, onLogout }: LayoutProps) {
  const location = useLocation();

  const handleLogout = () => {
    logout();
    onLogout();
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="flex">
        {/* Sidebar */}
        <div className="w-72 bg-slate-950/95 border-r border-slate-800 min-h-screen fixed left-0 top-0 backdrop-blur">
          <div className="p-6 border-b border-slate-800">
            <h1 className="text-2xl font-semibold text-white flex items-center gap-2">
              <Shield className="w-8 h-8 text-cyan-400" />
              NIDS
            </h1>
            <p className="text-slate-400 text-sm mt-1">Security Operations Console</p>
          </div>

          <nav className="mt-4 px-3">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={clsx(
                    'mb-1.5 flex items-center gap-3 rounded-xl px-4 py-2.5 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-300 hover:bg-slate-800/80 hover:text-slate-100'
                  )}
                >
                  <item.icon className="w-5 h-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-slate-800">
            <button
              onClick={handleLogout}
              className="flex items-center gap-3 px-4 py-2.5 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 rounded-xl w-full transition-colors"
            >
              <LogOut className="w-5 h-5" />
              Logout
            </button>
          </div>
        </div>

        {/* Main content */}
        <div className="ml-72 flex-1">
          <main className="p-6 md:p-8">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
