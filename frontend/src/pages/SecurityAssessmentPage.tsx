import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  Lock,
  Globe,
  FileCode
} from 'lucide-react';
import { apiClient } from '../api/client';
import { SecurityAssessment } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { ErrorState } from '../components/ErrorState';

export const SecurityAssessmentPage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [assessment, setAssessment] = useState<SecurityAssessment | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAssess = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const result = await apiClient.analyzeSecurity(url.trim());
      if (result) {
        setAssessment(result);
      } else {
        setError('Security assessment returned no header data.');
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Security assessment failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="border-b border-slate-800/80 pb-4">
        <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" />
          Passive Website Security Assessment
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Non-intrusive evaluation of HTTP security headers, cookie flags, TLS posture, and RFC 9116 security.txt endpoints.
        </p>
      </div>

      {/* Methodology Guardrail Notice */}
      <div className="rounded-xl border border-blue-500/30 bg-blue-950/20 p-4 space-y-1.5">
        <div className="flex items-center gap-2 text-blue-300 font-bold text-xs uppercase tracking-wider">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>Passive Observation Boundaries</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          TrustLens strictly avoids active exploitation, SQL injection, authentication bypass, script execution, or aggressive port scanning. Analysis is derived purely from standard publicly observable HTTP response headers.
        </p>
      </div>

      {/* Target Input */}
      <form onSubmit={handleAssess} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-xl">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative w-full">
            <Globe className="w-4 h-4 text-emerald-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter website URL (e.g., https://en.wikipedia.org or github.com)..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="w-full sm:w-auto px-6 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition whitespace-nowrap shadow-md shadow-emerald-950/40"
          >
            {loading ? 'Evaluating Headers...' : 'Run Passive Assessment'}
          </button>
        </div>
      </form>

      {error && <ErrorState message={error} />}

      {/* Assessment Results */}
      {assessment && (
        <div className="space-y-6 animate-fadeIn">
          {/* Header Posture Matrix */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              HTTP Security Header Audit
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {Object.entries(assessment.security_headers).map(([key, val]) => {
                const isConfigured = val && val !== 'Missing' && val !== 'Not configured';
                return (
                  <div
                    key={key}
                    className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3"
                  >
                    <div className="space-y-1 max-w-[80%]">
                      <span className="font-mono text-cyan-400 font-bold block">{key}</span>
                      <p className="font-mono text-slate-300 text-[11px] truncate">{String(val)}</p>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      isConfigured
                        ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/40'
                        : 'bg-amber-950/80 text-amber-300 border border-amber-500/40'
                    }`}>
                      {isConfigured ? 'Present' : 'Missing'}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Endpoints */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 font-bold uppercase text-[10px]">robots.txt Status</span>
                <p className="font-mono text-slate-200">{assessment.robots_txt_status}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 font-bold uppercase text-[10px]">security.txt (RFC 9116)</span>
                <p className="font-mono text-slate-200">{assessment.security_txt_status}</p>
              </div>
            </div>
          </div>

          {/* Detailed Passive Findings */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Passive Hardening Findings & Recommendations ({assessment.passive_findings.length})
            </h3>

            {assessment.passive_findings.length === 0 ? (
              <p className="text-xs text-slate-500">No passive hardening discrepancies detected.</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {assessment.passive_findings.map((f, i) => (
                  <div key={i} className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-xs font-bold text-white">{f.title}</span>
                      <RiskBadge level={f.severity} size="sm" />
                    </div>
                    <div className="rounded bg-slate-900 p-2 font-mono text-[11px] text-slate-300 border border-slate-800">
                      {f.evidence}
                    </div>
                    {f.impact && (
                      <p className="text-xs text-slate-300">
                        <strong className="text-amber-400">Impact: </strong>{f.impact}
                      </p>
                    )}
                    {f.remediation && (
                      <p className="text-xs text-slate-400">
                        <strong className="text-emerald-400">Remediation: </strong>{f.remediation}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
