import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Search,
  Lock,
  Shield,
  HelpCircle,
  Copy,
  Check,
  Radio,
  FileCheck2,
  Calendar,
  AlertTriangle
} from 'lucide-react';
import { apiClient } from '../api/client';
import { Investigation } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { FindingCard } from '../components/FindingCard';
import { EvidencePanel } from '../components/EvidencePanel';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';

export const InvestigationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'dns' | 'tls' | 'security' | 'feeds' | 'raw'>('overview');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (id) {
      setLoading(true);
      apiClient.getInvestigation(id)
        .then(setInvestigation)
        .catch((err) => setError(err?.response?.data?.detail || err.message || 'Record not found'))
        .finally(() => setLoading(false));
    }
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 bg-slate-800 rounded animate-pulse" />
        <LoadingSkeleton rows={4} height="h-28" />
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate(-1)} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition">
          <ArrowLeft className="w-4 h-4" />
          <span>Back</span>
        </button>
        <ErrorState message={error || 'Investigation record not found'} />
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top back navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/history')}
          className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-white transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Investigation History</span>
        </button>

        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-xs text-slate-300 hover:text-white transition"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Link Copied' : 'Share Report'}</span>
        </button>
      </div>

      {/* Main Forensic Report */}
      <div className="rounded-xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-900/90 to-slate-950 p-6 shadow-2xl space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-3">
              <RiskBadge level={investigation.overall_risk} size="lg" />
              <span className="text-xs font-mono text-slate-400">
                Confidence: <strong className="text-slate-200">{investigation.confidence}</strong>
              </span>
              <span className="text-xs font-mono text-slate-500 flex items-center gap-1">
                <Calendar className="w-3 h-3" />
                {new Date(investigation.created_at).toLocaleString()}
              </span>
            </div>
            <h1 className="text-lg sm:text-xl font-bold font-mono text-white break-all pt-2">
              {investigation.normalized_url}
            </h1>
            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-1 font-mono">
              <span>Host: <strong className="text-slate-300">{investigation.hostname}</strong></span>
              <span>Domain: <strong className="text-slate-300">{investigation.domain}</strong></span>
              {investigation.ip_address && (
                <span>IP: <strong className="text-slate-300">{investigation.ip_address}</strong></span>
              )}
            </div>
          </div>

          <div className="text-center px-5 py-3 rounded-xl bg-slate-950 border border-slate-800 shrink-0">
            <span className="text-2xl sm:text-3xl font-black font-mono text-white">
              {investigation.risk_score}
              <span className="text-xs text-slate-500 font-sans">/100</span>
            </span>
            <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
              Risk Score
            </p>
          </div>
        </div>

        {/* English Explanation Summary */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            Diagnostic Security Summary
          </h3>
          <p className="text-sm text-slate-200 leading-relaxed bg-slate-950/60 p-4 rounded-lg border border-slate-800">
            {investigation.summary}
          </p>
        </div>
      </div>

      {/* Drill-down Findings */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider">
          Forensic Findings & Evidence ({investigation.findings.length})
        </h3>
        {investigation.findings.length === 0 ? (
          <p className="text-xs text-slate-500 p-4 rounded-lg bg-slate-900 border border-slate-800">
            No anomalous indicators detected.
          </p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {investigation.findings.map((f, idx) => (
              <FindingCard key={idx} finding={f} />
            ))}
          </div>
        )}
      </div>

      {/* Raw Payload Section */}
      <EvidencePanel title="Complete Canonical JSON Record" data={investigation} defaultExpanded={false} />
    </div>
  );
};
