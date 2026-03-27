import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Shield, 
  Globe, 
  Brain, 
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
  { name: 'Rules', href: '/rules', icon: Shield },
  { name: 'Threat Map', href: '/threat-map', icon: Globe },
  { name: 'ML Monitor', href: '/ml-monitor', icon: Brain },
  { name: 'Settings', href: '/settings', icon: SettingsIcon },
];

export default function Layout({ children, onLogout }: LayoutProps) {
  const location = useLocation();

  const handleLogout = () => {
    logout();
    onLogout();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="flex">
        {/* Sidebar */}
        <div className="w-64 bg-gray-900 min-h-screen fixed left-0 top-0">
          <div className="p-6">
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="w-8 h-8 text-blue-400" />
              NIDS
            </h1>
            <p className="text-gray-400 text-sm mt-1">Network Intrusion Detection</p>
          </div>

          <nav className="mt-8">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={clsx(
                    'flex items-center gap-3 px-6 py-3 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-gray-800 text-white border-l-4 border-blue-500'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  )}
                >
                  <item.icon className="w-5 h-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          <div className="absolute bottom-0 left-0 right-0 p-6">
            <button
              onClick={handleLogout}
              className="flex items-center gap-3 px-4 py-2 text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-800 rounded-lg w-full transition-colors"
            >
              <LogOut className="w-5 h-5" />
              Logout
            </button>
          </div>
        </div>

        {/* Main content */}
        <div className="ml-64 flex-1">
          <main className="p-8">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
