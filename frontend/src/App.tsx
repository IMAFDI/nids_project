import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState } from 'react';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Events from './pages/Events';
import Rules from './pages/Rules';
import Cases from './pages/Cases';
import Playbooks from './pages/Playbooks';
import ThreatMap from './pages/ThreatMap';
import MLMonitor from './pages/MLMonitor';
import Settings from './pages/Settings';
import ProfilePage from './pages/Profile';
import OpsPlatform from './pages/OpsPlatform';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('nids_token'));

  const handleLogin = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <BrowserRouter>
      <Layout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Events />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/playbooks" element={<Playbooks />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/threat-map" element={<ThreatMap />} />
          <Route path="/ml-monitor" element={<MLMonitor />} />
          <Route path="/ops-platform" element={<OpsPlatform />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
