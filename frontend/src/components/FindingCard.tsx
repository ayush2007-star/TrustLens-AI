import React from 'react';
import { AlertCircle, ShieldAlert, Info, AlertTriangle } from 'lucide-react';
import { URLFinding } from '../types';
import { RiskBadge } from './RiskBadge';

interface FindingCardProps {
  finding: URLFinding;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding }) => {
  const getIcon = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />;
      case 'MEDIUM':
        return <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />;
      default:
        return <Info className="w-5 h-5 text-blue-400 shrink-0" />;
    }
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-3 transition hover:border-slate-700">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          {getIcon(finding.severity)}
          <div>
            <h4 className="text-sm font-semibold text-white">
              {finding.finding_title}
            </h4>
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              Category: {finding.category}
            </span>
          </div>
        </div>
        <RiskBadge level={finding.severity} size="sm" />
      </div>

      <div className="rounded bg-slate-950/80 p-2.5 border border-slate-800/80 font-mono text-xs text-slate-300 break-all">
        <span className="text-slate-500 font-semibold block text-[10px] uppercase mb-1">Evidence:</span>
        {finding.evidence}
      </div>

      {finding.impact && (
        <p className="text-xs text-slate-300">
          <span className="font-semibold text-rose-400/90">Potential Impact: </span>
          {finding.impact}
        </p>
      )}

      {finding.remediation && (
        <p className="text-xs text-slate-400">
          <span className="font-semibold text-emerald-400/90">Recommended Action: </span>
          {finding.remediation}
        </p>
      )}
    </div>
  );
};
