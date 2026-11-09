import React, { useState } from 'react';
import {
  Lock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  ExternalLink,
  Info,
  Calendar,
  KeyRound,
  FileCheck2
} from 'lucide-react';
import { apiClient } from '../api/client';
import { TLSReport } from '../types';
import { ErrorState } from '../components/ErrorState';

export const TlsAnalysisPage: React.FC = () => {
  const [hostname, setHostname] = useState('');
  const [loading, setLoading] = useState(false);
  const [tlsReport, setTlsReport] = useState<TLSReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleInspect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim()) return;
    setLoading(true);
    setError(null);
    try {
      // Trigger investigation on target and extract TLS report
      const report = await apiClient.analyzeTls(hostname.trim());
      if (report) {
        setTlsReport(report);
      } else {
        setError('TLS inspection returned no certificate data for this host.');
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'TLS inspection failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="border-b border-slate-800/80 pb-4">
        <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-cyan-400" />
          TLS Certificate & Digital Trust Inspector
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Inspect public X.509 certificate metadata, hostname matching, validity, and negotiated TLS version.
        </p>
      </div>

      {/* Critical Educational Notice */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-5 space-y-2">
        <div className="flex items-center gap-2 text-amber-400 font-bold text-xs uppercase tracking-wider">
          <AlertTriangle className="w-4 h-4" />
          <span>Fundamental Principle of Web Trust</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          "A valid HTTPS certificate confirms aspects of encrypted connection and certificate identity. <strong>It does not establish that a website or its business is trustworthy.</strong> Furthermore, an external TLS inspection cannot prove whether a Certificate Authority's internal private key generation was cryptographically sound."
        </p>
      </div>

      {/* Host Input Form */}
      <form onSubmit={handleInspect} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-xl">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative w-full">
            <Lock className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="Enter HTTPS domain (e.g. github.com, en.wikipedia.org, example.com)..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !hostname.trim()}
            className="w-full sm:w-auto px-6 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition whitespace-nowrap shadow-md shadow-cyan-950/40"
          >
            {loading ? 'Inspecting Handshake...' : 'Inspect Certificate'}
          </button>
        </div>
      </form>

      {error && <ErrorState message={error} />}

      {/* TLS Certificate Forensic Display */}
      {tlsReport && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-2xl space-y-6 animate-fadeIn">
          {/* Validity Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
            <div className="space-y-1">
              <span className="text-[10px] font-mono font-bold text-slate-500 uppercase">
                Handshake Status
              </span>
              <div className="flex items-center gap-2">
                <span className={`text-base font-bold font-mono px-3 py-1 rounded border ${
                  tlsReport.is_valid
                    ? 'bg-emerald-950/70 text-emerald-300 border-emerald-500/40'
                    : 'bg-rose-950/80 text-rose-300 border-rose-500/40'
                }`}>
                  {tlsReport.status_text}
                </span>
                <span className="text-xs font-mono text-cyan-400 bg-slate-950 border border-slate-800 px-2 py-1 rounded">
                  {tlsReport.tls_version || 'Not negotiated'}
                </span>
              </div>
            </div>

            <div className="text-center px-4 py-2 rounded-xl bg-slate-950 border border-slate-800 shrink-0">
              <span className="text-xl font-black font-mono text-white">
                {tlsReport.days_remaining ?? 'N/A'}
                <span className="text-xs text-slate-500 font-sans ml-1">days</span>
              </span>
              <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
                Remaining Validity
              </p>
            </div>
          </div>

          {/* Core Properties Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-500 uppercase font-bold text-[10px] block">Public Key Algorithm</span>
              <span className="text-slate-200 font-bold">{tlsReport.key_type}</span>
              <span className="text-slate-400 block">{tlsReport.key_size ? `${tlsReport.key_size} bits` : ''}</span>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-500 uppercase font-bold text-[10px] block">Signature Algorithm</span>
              <span className="text-slate-200 truncate block">{tlsReport.signature_algorithm}</span>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-500 uppercase font-bold text-[10px] block">Not Before (Activation)</span>
              <span className="text-slate-300">{tlsReport.not_before ? new Date(tlsReport.not_before).toLocaleDateString() : 'N/A'}</span>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-500 uppercase font-bold text-[10px] block">Not After (Expiration)</span>
              <span className="text-slate-300">{tlsReport.not_after ? new Date(tlsReport.not_after).toLocaleDateString() : 'N/A'}</span>
            </div>
          </div>

          {/* Subject & Issuer Detailed Blocks */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Subject Identity (Owner)</h4>
              <pre className="font-mono text-slate-300 whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(tlsReport.subject, null, 2)}
              </pre>
            </div>
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Certificate Issuer</h4>
              <pre className="font-mono text-slate-300 whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(tlsReport.issuer, null, 2)}
              </pre>
            </div>
          </div>

          {/* Subject Alternative Names (SANs) */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider">
              Covered Subject Alternative Names (SANs) ({tlsReport.san_list.length})
            </h4>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {tlsReport.san_list.map((san, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-xs font-mono bg-slate-900 border border-slate-800 text-cyan-300"
                >
                  {san}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
