import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  CheckCircle,
  AlertTriangle,
  ShieldCheck,
  Search,
  ExternalLink,
  Copy,
  Check,
  Hash,
  Database,
  ArrowRight,
  RefreshCw,
  Code2
} from 'lucide-react';
import { apiClient } from '../api/client';
import { RegistryEntry, RegistryVerification } from '../types';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';

export const DigitalTrustRegistryPage: React.FC = () => {
  const [entries, setEntries] = useState<RegistryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Verification states
  const [verifyReportId, setVerifyReportId] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<RegistryVerification | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fetchLedger = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getRegistryLedger();
      setEntries(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load cryptographic ledger.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLedger();
  }, []);

  const handleVerify = async (reportIdToVerify: string) => {
    if (!reportIdToVerify.trim()) return;
    setVerifying(true);
    setVerificationResult(null);
    try {
      const res = await apiClient.verifyRegistryReport(reportIdToVerify.trim());
      setVerificationResult(res);
    } catch (err: any) {
      alert('Verification query failed: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
            <FileCheck2 className="w-6 h-6 text-cyan-400" />
            Tamper-Evident Digital Trust Registry
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Immutable SHA-256 cryptographic hash-chained ledger guaranteeing report authenticity and historical non-repudiation.
          </p>
        </div>
        <button
          onClick={fetchLedger}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-xs font-semibold text-slate-300 hover:text-white transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Sync Ledger</span>
        </button>
      </div>

      {/* Truth vs Integrity Educational Callout */}
      <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-5 space-y-2">
        <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase tracking-wider">
          <Hash className="w-4 h-4" />
          <span>Cryptographic Proof Guarantee</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          "The hash registry mathematically proves the <strong>integrity of recorded content</strong> (guaranteeing that a report has not been modified or deleted after registration). It does not guarantee that the submitter's initial claim was inherently accurate. No passwords, OTPs, or private data are ever exposed on the public ledger."
        </p>
        <div className="pt-2 flex items-center gap-2 text-[11px] text-slate-400 font-mono">
          <Code2 className="w-3.5 h-3.5 text-cyan-400" />
          <span>Optional EVM Smart Contract: Included in repository under <code>contracts/TrustLensRegistry.sol</code></span>
        </div>
      </div>

      {/* Real-Time Hash Verification Tool */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Real-Time Cryptographic Verification
        </h3>
        <p className="text-xs text-slate-400">
          Enter a threat report UUID or select a block from below to re-compute its SHA-256 fingerprint from live database state.
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <input
            type="text"
            value={verifyReportId}
            onChange={(e) => setVerifyReportId(e.target.value)}
            placeholder="Enter Threat Report ID (e.g., from ledger table below)..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            onClick={() => handleVerify(verifyReportId)}
            disabled={verifying || !verifyReportId.trim()}
            className="w-full sm:w-auto px-6 py-2.5 rounded-lg text-xs font-bold uppercase tracking-wider bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition whitespace-nowrap shadow-md shadow-cyan-950/40"
          >
            {verifying ? 'Auditing Hash Chain...' : 'Verify Fingerprint'}
          </button>
        </div>

        {/* Verification Result Card */}
        {verificationResult && (
          <div className={`p-4 rounded-lg border text-xs font-mono space-y-2 animate-fadeIn ${
            verificationResult.status === 'VERIFIED_AUTHENTIC'
              ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-200'
              : verificationResult.status === 'TAMPER_DETECTED'
              ? 'bg-rose-950/60 border-rose-500/60 text-rose-200'
              : 'bg-slate-950 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center justify-between">
              <span className="font-bold text-sm tracking-wide">
                STATUS: {verificationResult.status}
              </span>
              {verificationResult.block_index !== undefined && (
                <span className="px-2 py-0.5 rounded bg-black/40 border border-current">
                  Block #{verificationResult.block_index}
                </span>
              )}
            </div>

            <p className="text-xs leading-relaxed font-sans">{verificationResult.details}</p>

            {verificationResult.is_registered && (
              <div className="space-y-1.5 pt-2 text-[11px] text-slate-300 border-t border-current/20">
                <div className="truncate">
                  <strong>Stored Data Hash:</strong> {verificationResult.stored_data_hash}
                </div>
                <div className="truncate">
                  <strong>Re-computed Hash:</strong> {verificationResult.computed_data_hash}
                </div>
                <div className="truncate">
                  <strong>Chained Block Hash:</strong> {verificationResult.stored_chained_hash}
                </div>
                <div className="truncate">
                  <strong>Previous Block Hash:</strong> {verificationResult.previous_hash}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {loading && <LoadingSkeleton rows={5} height="h-20" />}
      {error && !loading && <ErrorState message={error} onRetry={fetchLedger} />}

      {/* Ledger History Table */}
      {!loading && !error && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl space-y-4 p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              Cryptographic Ledger History ({entries.length} Blocks)
            </h3>
            <span className="text-[11px] font-mono text-cyan-400">SHA-256 Hash Chained</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2.5 px-3">Block #</th>
                  <th className="py-2.5 px-3">Target Domain</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Chained Fingerprint</th>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3 text-right">Audit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {entries.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                      No threat reports committed to the ledger yet. Submit a report from Threat Intel to create Block #0.
                    </td>
                  </tr>
                ) : (
                  entries.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-3 font-bold text-cyan-400">
                        #{entry.block_index}
                      </td>
                      <td className="py-3 px-3 text-white font-semibold">
                        {entry.target_domain}
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px]">
                          {entry.report_type}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <button
                          onClick={() => copyToClipboard(entry.chained_hash, entry.id)}
                          className="flex items-center gap-1.5 text-[11px] text-slate-400 hover:text-cyan-300 transition"
                          title="Click to copy full hash"
                        >
                          <span>{entry.chained_hash.slice(0, 16)}...</span>
                          {copiedHash === entry.id ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3 text-slate-500" />
                          )}
                        </button>
                      </td>
                      <td className="py-3 px-3 text-slate-400 text-[11px]">
                        {new Date(entry.registered_at).toISOString().slice(0, 19).replace('T', ' ')}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => {
                            setVerifyReportId(entry.report_id);
                            handleVerify(entry.report_id);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px] font-sans font-semibold transition"
                        >
                          Verify
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
