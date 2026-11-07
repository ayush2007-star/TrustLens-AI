import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Search,
  MessageSquareWarning,
  Lock,
  ShieldCheck,
  Radio,
  Network,
  FileCheck2,
  History,
  BookOpen,
  Home
} from 'lucide-react';
import { BrandLogo } from './BrandLogo';

export const Sidebar: React.FC = () => {
  const navItems = [
    { to: '/', label: 'Home', icon: Home, exact: true },
    { to: '/dashboard', label: 'Security Dashboard', icon: LayoutDashboard },
    { to: '/investigate', label: 'Investigate URL', icon: Search },
    { to: '/message-analyzer', label: 'Message Analyzer', icon: MessageSquareWarning },
    { to: '/tls-trust', label: 'TLS & Digital Trust', icon: Lock },
    { to: '/security-assessment', label: 'Security Assessment', icon: ShieldCheck },
    { to: '/threat-intel', label: 'Threat Intelligence', icon: Radio },
    { to: '/threat-correlation', label: 'Threat Correlation', icon: Network },
    { to: '/trust-registry', label: 'Digital Trust Registry', icon: FileCheck2 },
    { to: '/history', label: 'Investigation History', icon: History },
    { to: '/methodology', label: 'Methodology & About', icon: BookOpen },
  ];

  return (
    <aside className="w-64 shrink-0 bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between hidden md:flex min-h-screen">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-800/80">
          <NavLink to="/">
            <BrandLogo size="md" showTagline={true} />
          </NavLink>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.exact}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Footer Status */}
      <div className="p-4 m-3 rounded-lg border border-slate-800/80 bg-slate-900/40">
        <div className="flex items-center gap-2 mb-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="text-[11px] font-semibold tracking-wider uppercase text-emerald-400">
            Threat Engine Online
          </span>
        </div>
        <p className="text-[10px] text-slate-400 leading-normal">
          SSRF Filter & Cryptographic Ledger active. 0 JS execution policy enforced.
        </p>
      </div>
    </aside>
  );
};
