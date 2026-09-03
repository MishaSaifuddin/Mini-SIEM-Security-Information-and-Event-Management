import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { authService } from '../services';

const icons = {
  dashboard: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  ),
  events: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="8" y1="13" x2="16" y2="13" />
      <line x1="8" y1="17" x2="16" y2="17" />
    </svg>
  ),
  alerts: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  ),
  rules: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 20h9" />
      <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
    </svg>
  ),
  sources: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <path d="M8 14s1.5 2 4 2 4-2 4-2" />
      <line x1="9" y1="9" x2="9.01" y2="9" />
      <line x1="15" y1="9" x2="15.01" y2="9" />
    </svg>
  ),
};

function Layout({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [openAlerts, setOpenAlerts] = useState(0);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await authService.getMe();
        setUser(res.data);
      } catch (e) {
        // will redirect via interceptor
      }
    };
    fetchUser();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  const navItems = [
    { path: '/', label: 'Dashboard', icon: icons.dashboard, exact: true },
    { path: '/events', label: 'Events', icon: icons.events },
    { path: '/alerts', label: 'Alerts', icon: icons.alerts },
    { path: '/rules', label: 'Detection Rules', icon: icons.rules },
    { path: '/sources', label: 'Log Sources', icon: icons.sources },
  ];

  const pageTitles = {
    '/': 'Security Dashboard',
    '/events': 'Event Explorer',
    '/alerts': 'Alert Management',
    '/rules': 'Detection Rules',
    '/sources': 'Log Sources',
  };

  const currentTitle = pageTitles[location.pathname] || 'Mini SIEM';

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">S</div>
          <div>
            <h2>Mini SIEM</h2>
            <span>Security Operations</span>
          </div>
        </div>
        <div className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.exact}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              {item.icon}
              <span>{item.label}</span>
            </NavLink>
          ))}
        </div>
        <div className="sidebar-footer">
          {user && (
            <div className="user-info">
              <div className="user-avatar">
                {user.username.charAt(0).toUpperCase()}
              </div>
              <div>
                <div className="user-name">{user.username}</div>
                <div className="user-role">{user.role}</div>
              </div>
            </div>
          )}
          <button className="logout-btn" onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      </nav>

      <main className="main-content">
        <div className="topbar">
          <h1>{currentTitle}</h1>
        </div>
        {children}
      </main>
    </div>
  );
}

export default Layout;
