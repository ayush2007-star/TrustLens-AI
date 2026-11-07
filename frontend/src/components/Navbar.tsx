import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { Menu, X, Shield, Activity, Terminal, ArrowRight } from 'lucide-react';
import { BrandLogo } from './BrandLogo';
import { apiClient } from '../api/client';

export const Navbar: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [systemHealthy, setSystemHealthy] = useState<boolean | null>(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    apiClient.getHealth()
      .then(() => setSystemHealthy(true))
      .catch(() => setSystemHealthy(false));
  }, []);

  const navLinks = [
    { to: '/dashboard', label: 'Dashboard' },
    { to: '/investigate', label: 'Investigate URL' },
    { to: '/message-analyzer', label: 'Message Analyzer' },
    { to: '/tls-trust', label: 'TLS Trust' },
    { to: '/threat-intel', label: 'Threat Intel' },
    { to: '/trust-registry', label: 'Trust Registry' },
    { to: '/history', label: 'History' },
    { to: '/methodology', label: 'Methodology' },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
      <div className="flex h-16 items-center justify-between px-4 sm:px-6">
        <div className="flex items-center gap-4">
          <div className="md:hidden">
            <NavLink to="/">
              <BrandLogo size="sm" />
            </NavLink>
          </div>

          {/* Active section breadcrumb */}
          <div className="hidden md:flex items-center gap-2 text-xs text-slate-400 font-mono">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>trustlens-ai</span>
            <span>/</span>
            <span className="text-slate-200 capitalize">
              {location.pathname === '/' ? 'Home' : location.pathname.replace('/', '').replace('-', ' ')}
            </span>
          </div>
        </div>

        {/* Right tools: Engine status & Action */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs">
            <Activity className={`w-3.5 h-3.5 ${systemHealthy === true ? 'text-emerald-400' : 'text-amber-400'}`} />
            <span className="text-[11px] font-mono text-slate-300">
              API: {systemHealthy === true ? 'ONLINE' : systemHealthy === false ? 'CONNECTING' : 'CHECKING...'}
            </span>
          </div>

          <button
            onClick={() => navigate('/investigate')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-sm shadow-cyan-900/30"
          >
            <span>Scan URL</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>

          {/* Mobile hamburger button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 text-slate-400 hover:text-white"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-slate-800 bg-slate-950 p-4 space-y-2 animate-fadeIn">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              onClick={() => setMobileMenuOpen(false)}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-xs font-semibold tracking-wide transition ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-900'
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </div>
      )}
    </header>
  );
};
