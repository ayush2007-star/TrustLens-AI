import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Skull, HelpCircle } from 'lucide-react';
import { RiskLevel, SeverityLevel } from '../types';

interface RiskBadgeProps {
  level: RiskLevel | SeverityLevel | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = 'md', showIcon = true }) => {
  const normalized = level.toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let Icon = HelpCircle;

  if (normalized.includes('LOW') || normalized === 'INFO') {
    colorClasses = 'bg-emerald-950/70 text-emerald-300 border-emerald-500/40 shadow-emerald-950/30';
    Icon = ShieldCheck;
  } else if (normalized.includes('SUSPICIOUS') || normalized === 'MEDIUM') {
    colorClasses = 'bg-amber-950/70 text-amber-300 border-amber-500/40 shadow-amber-950/30';
    Icon = AlertTriangle;
  } else if (normalized.includes('HIGH')) {
    colorClasses = 'bg-rose-950/80 text-rose-300 border-rose-500/40 shadow-rose-950/30';
    Icon = ShieldAlert;
  } else if (normalized.includes('MALICIOUS') || normalized === 'CRITICAL') {
    colorClasses = 'bg-red-950 text-red-200 border-red-500/60 shadow-red-950/40 font-bold';
    Icon = Skull;
  } else if (normalized.includes('INCONCLUSIVE')) {
    colorClasses = 'bg-slate-900 text-slate-400 border-slate-700';
    Icon = HelpCircle;
  }

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-medium',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-semibold'
  };

  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4 h-4'
  };

  return (
    <span className={`inline-flex items-center rounded-md border shadow-sm tracking-wide ${colorClasses} ${sizeClasses[size]}`}>
      {showIcon && <Icon className={iconSizes[size]} />}
      <span>{normalized}</span>
    </span>
  );
};
