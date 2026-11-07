import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'blue' | 'cyan' | 'red' | 'amber' | 'emerald' | 'purple';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'blue'
}) => {
  const variantStyles = {
    blue: {
      bg: 'from-blue-950/40 to-slate-900',
      border: 'border-blue-900/40',
      iconBg: 'bg-blue-900/30 text-blue-400 border-blue-500/20'
    },
    cyan: {
      bg: 'from-cyan-950/40 to-slate-900',
      border: 'border-cyan-900/40',
      iconBg: 'bg-cyan-900/30 text-cyan-400 border-cyan-500/20'
    },
    red: {
      bg: 'from-rose-950/40 to-slate-900',
      border: 'border-rose-900/40',
      iconBg: 'bg-rose-900/30 text-rose-400 border-rose-500/20'
    },
    amber: {
      bg: 'from-amber-950/40 to-slate-900',
      border: 'border-amber-900/40',
      iconBg: 'bg-amber-900/30 text-amber-400 border-amber-500/20'
    },
    emerald: {
      bg: 'from-emerald-950/40 to-slate-900',
      border: 'border-emerald-900/40',
      iconBg: 'bg-emerald-900/30 text-emerald-400 border-emerald-500/20'
    },
    purple: {
      bg: 'from-purple-950/40 to-slate-900',
      border: 'border-purple-900/40',
      iconBg: 'bg-purple-900/30 text-purple-400 border-purple-500/20'
    }
  };

  const style = variantStyles[variant];

  return (
    <div className={`relative overflow-hidden rounded-xl border bg-gradient-to-br ${style.bg} ${style.border} p-5 shadow-lg transition-all hover:border-slate-700`}>
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">
            {title}
          </p>
          <p className="text-2xl font-black tracking-tight text-white sm:text-3xl font-mono">
            {value}
          </p>
          {subtitle && (
            <p className="text-xs text-gray-400">
              {subtitle}
            </p>
          )}
        </div>
        <div className={`rounded-lg border p-2.5 ${style.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
