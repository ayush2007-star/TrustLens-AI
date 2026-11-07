import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Search,
  Shield,
  AlertTriangle,
  Lock,
  Globe,
  Radio,
  ExternalLink,
  ChevronRight,
  ArrowRight,
  Share2,
  FileCheck2,
  CheckCircle2,
  HelpCircle,
  Copy,
  Check
} from 'lucide-react';
import { apiClient } from '../api/client';
import { Investigation, URLFinding } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { FindingCard } from '../components/FindingCard';
import { EvidencePanel } from '../components/EvidencePanel';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';

export const InvestigateUrlPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [url, setUrl] = useState(searchParams.get('target') || '');
  const [loading, setLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'dns' | 'tls' | 'security' | 'feeds' | 'raw'>('overview');
  const [copiedUrl, setCopiedUrl] = useState(false);

  const steps = [
    'Normalizing URL & inspecting syntax...',
    'Resolving DNS resource records & WHOIS age...',
    'Tracing HTTP redirect chains safely (SSRF guard)...',
    'Executing TLS handshake & parsing X.509 cert...',
    'Performing passive HTTP header & cookie assessment...',
    'Cross-referencing threat intelligence feeds & scoring risk...'
  ];

  const runInvestigation = async (targetToScan: string) => {
    if (!targetToScan.trim()) return;
    setLoading(true);
    setError(null);
    setCurrentStep(0);

    // Simulate stepped progress during backend request
    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 400);

    try {
      const result = await apiClient.investigateUrl(targetToScan.trim());
      clearInterval(stepInterval);
      setInvestigation(result);
      setActiveTab('overview');
    } catch (err: any) {
      clearInterval(stepInterval);
      setError(err?.response?.data?.detail || err?.response?.data?.message || err.message || 'Investigation failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const target = searchParams.get('target');
    if (target) {
      setUrl(target);
      runInvestigation(target);
    }
  }, [searchParams]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runInvestigation(url);
  };

  const handleCopyLink = () => {
    if (investigation) {
      navigator.clipboard.writeText(window.location.origin + `/investigations/${investigation.id}`);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    }
  };

  return (
    <div className="space-y-8">
      {/* Search Header */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div>
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
              <Search className="w-6 h-6 text-cyan-400" />
              URL & Website Investigation
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Multi-vector passive security analysis, digital trust verification, and explainable risk classification.
            </p>
          </div>
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSubmit} className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 shadow-xl space-y-3">
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="relative w-full">
              <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL or domain (e.g., https://paypal-security-update.example.com/login)..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
                disabled={loading}
              />
            </div>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="w-full sm:w-auto px-6 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition whitespace-nowrap shadow-lg shadow-cyan-950/40"
            >
              {loading ? 'Analyzing...' : 'Investigate'}
            </button>
          </div>

          {/* Test Case Quick Chips */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-400">
            <span className="font-semibold text-slate-500 text-[11px] uppercase">Quick Benchmarks:</span>
            <button
              type="button"
              onClick={() => { setUrl('https://paypal-security-update.example.com/login?token=urgent'); runInvestigation('https://paypal-security-update.example.com/login?token=urgent'); }}
              className="px-2 py-0.5 rounded bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 font-mono text-[11px] transition"
            >
              ⚠️ PayPal Typosquat (Synthetic)
            </button>
            <button
              type="button"
              onClick={() => { setUrl('http://198.51.100.42:8080/banking/verification'); runInvestigation('http://198.51.100.42:8080/banking/verification'); }}
              className="px-2 py-0.5 rounded bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 font-mono text-[11px] transition"
            >
              ⚠️ Raw IP & Port (Synthetic)
            </button>
            <button
              type="button"
              onClick={() => { setUrl('https://en.wikipedia.org'); runInvestigation('https://en.wikipedia.org'); }}
              className="px-2 py-0.5 rounded bg-emerald-950/50 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/40 font-mono text-[11px] transition"
            >
              ✓ Wikipedia (Benign)
            </button>
          </div>
        </form>
      </div>

      {/* Analysis Stepper during Loading */}
      {loading && (
        <div className="p-8 rounded-xl border border-slate-800 bg-slate-900/40 space-y-6 animate-fadeIn">
          <div className="space-y-2 text-center">
            <div className="inline-flex p-3 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-500/30 animate-pulse">
              <Search className="w-6 h-6" />
            </div>
            <h3 className="text-base font-semibold text-white">Investigating Target</h3>
            <p className="text-xs text-slate-400 font-mono">{url}</p>
          </div>

          <div className="max-w-md mx-auto space-y-3">
            {steps.map((stepText, idx) => (
              <div key={idx} className="flex items-center gap-3 text-xs">
                {idx < currentStep ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : idx === currentStep ? (
                  <span className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin shrink-0" />
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-700 bg-slate-800 shrink-0" />
                )}
                <span className={idx <= currentStep ? 'text-slate-200' : 'text-slate-600'}>
                  {stepText}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {error && !loading && (
        <ErrorState message={error} onRetry={() => runInvestigation(url)} />
      )}

      {/* Investigation Results */}
      {investigation && !loading && (
        <div className="space-y-6 animate-fadeIn">
          {/* Synthetic Demo Warning Banner if applicable */}
          {investigation.is_synthetic_demo && (
            <div className="flex items-center gap-2 p-3 rounded-lg border border-amber-500/40 bg-amber-950/30 text-xs text-amber-300">
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
              <span>
                <strong>SYNTHETIC DEMO BENCHMARK:</strong> This target is an RFC-reserved test case. Findings simulate realistic attacker kit signatures without probing third-party networks.
              </span>
            </div>
          )}

          {/* Verdict Hero Card */}
          <div className="rounded-xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-900/90 to-slate-950 p-6 shadow-2xl space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-3">
                  <RiskBadge level={investigation.overall_risk} size="lg" />
                  <span className="text-xs font-mono text-slate-400">
                    Confidence: <strong className="text-slate-200">{investigation.confidence}</strong>
                  </span>
                </div>
                <h2 className="text-lg sm:text-xl font-bold font-mono text-white break-all pt-2">
                  {investigation.normalized_url}
                </h2>
                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-1 font-mono">
                  <span>Host: <strong className="text-slate-300">{investigation.hostname}</strong></span>
                  <span>Domain: <strong className="text-slate-300">{investigation.domain}</strong></span>
                  {investigation.ip_address && (
                    <span>IP: <strong className="text-slate-300">{investigation.ip_address}</strong></span>
                  )}
                </div>
              </div>

              {/* Score Gauge */}
              <div className="flex items-center gap-4 shrink-0">
                <div className="text-center px-4 py-2 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-2xl sm:text-3xl font-black font-mono text-white">
                    {investigation.risk_score}
                    <span className="text-xs text-slate-500 font-sans">/100</span>
                  </span>
                  <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
                    Risk Score
                  </p>
                </div>

                <button
                  onClick={handleCopyLink}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 bg-slate-900 text-xs text-slate-300 hover:text-white transition"
                  title="Share / Copy report link"
                >
                  {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedUrl ? 'Copied' : 'Share'}</span>
                </button>
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

            {/* Analysis Limitations Notice */}
            {investigation.analysis_limitations.length > 0 && (
              <div className="rounded-lg bg-slate-950/40 p-3 border border-slate-800/80 space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                  <HelpCircle className="w-3 h-3" />
                  Analysis Constraints & Transparency
                </span>
                <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                  {investigation.analysis_limitations.map((lim, i) => (
                    <li key={i}>{lim}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Drill-Down Tabs */}
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-2">
              {[
                { id: 'overview', label: `Findings (${investigation.findings.length})` },
                { id: 'dns', label: 'Domain & DNS Intel' },
                { id: 'tls', label: 'TLS & Digital Trust' },
                { id: 'security', label: 'Passive Security' },
                { id: 'feeds', label: `Threat Feeds (${investigation.threat_intel_matches.length})` },
                { id: 'raw', label: 'Raw Evidence' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold tracking-wide transition ${
                    activeTab === tab.id
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab 1: Findings Overview */}
            {activeTab === 'overview' && (
              <div className="space-y-4">
                {investigation.findings.length === 0 ? (
                  <div className="p-8 text-center rounded-xl bg-slate-900/30 border border-slate-800 text-xs text-slate-400">
                    No deceptive static indicators identified in URL syntax or authority.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {investigation.findings.map((f, idx) => (
                      <FindingCard key={idx} finding={f} />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Tab 2: DNS & Domain Intel */}
            {activeTab === 'dns' && (
              <div className="space-y-4">
                {investigation.domain_info ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase font-semibold">Registrar</span>
                        <p className="text-xs font-mono text-slate-200 mt-1">{investigation.domain_info.registrar || 'Not available'}</p>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase font-semibold">Created Date</span>
                        <p className="text-xs font-mono text-slate-200 mt-1">{investigation.domain_info.creation_date || 'Not available'}</p>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase font-semibold">Domain Age</span>
                        <p className="text-xs font-mono text-slate-200 mt-1">
                          {investigation.domain_info.age_days ? `${investigation.domain_info.age_days} days` : 'Not available'}
                        </p>
                      </div>
                    </div>

                    <div className="space-y-3 pt-2">
                      <h4 className="text-xs font-bold text-white uppercase tracking-wider">DNS Records</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                          <span className="text-cyan-400 font-bold">A Records (IPv4):</span>
                          {investigation.domain_info.a_records.length > 0 ? (
                            investigation.domain_info.a_records.map((ip, i) => <div key={i} className="text-slate-300">{ip}</div>)
                          ) : <div className="text-slate-500">None</div>}
                        </div>
                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                          <span className="text-cyan-400 font-bold">Nameservers:</span>
                          {investigation.domain_info.nameservers.length > 0 ? (
                            investigation.domain_info.nameservers.map((ns, i) => <div key={i} className="text-slate-300">{ns}</div>)
                          ) : <div className="text-slate-500">None</div>}
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Domain intelligence not available.</p>
                )}
              </div>
            )}

            {/* Tab 3: TLS & Digital Trust */}
            {activeTab === 'tls' && (
              <div className="space-y-4">
                {investigation.tls_report ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div className="flex items-center gap-2">
                        <Lock className="w-5 h-5 text-cyan-400" />
                        <h4 className="text-sm font-semibold text-white">X.509 Certificate Report</h4>
                      </div>
                      <span className={`text-xs font-mono px-2.5 py-1 rounded border font-semibold ${
                        investigation.tls_report.is_valid
                          ? 'bg-emerald-950/70 text-emerald-300 border-emerald-500/40'
                          : 'bg-rose-950/80 text-rose-300 border-rose-500/40'
                      }`}>
                        {investigation.tls_report.status_text}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase font-bold block">TLS Version</span>
                        <span className="font-mono text-slate-200">{investigation.tls_report.tls_version || 'Unknown'}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase font-bold block">Signature Algorithm</span>
                        <span className="font-mono text-slate-200">{investigation.tls_report.signature_algorithm || 'Unknown'}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase font-bold block">Key Type / Size</span>
                        <span className="font-mono text-slate-200">
                          {investigation.tls_report.key_type} {investigation.tls_report.key_size ? `(${investigation.tls_report.key_size} bits)` : ''}
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase font-bold block">Days Remaining</span>
                        <span className="font-mono text-slate-200">{investigation.tls_report.days_remaining ?? 'N/A'}</span>
                      </div>
                    </div>

                    {/* SANs */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">Subject Alternative Names (SANs)</span>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {investigation.tls_report.san_list.map((san, i) => (
                          <span key={i} className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800">
                            {san}
                          </span>
                        ))}
                      </div>
                    </div>

                    <p className="text-xs text-slate-400 bg-slate-950/40 p-3 rounded-lg border border-slate-800/80 italic">
                      {investigation.tls_report.limitation_notes}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">TLS analysis not available.</p>
                )}
              </div>
            )}

            {/* Tab 4: Passive Security */}
            {activeTab === 'security' && (
              <div className="space-y-4">
                {investigation.security_assessment ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-4">
                    <h4 className="text-xs font-bold text-white uppercase tracking-wider">Observable Security Headers</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                      {Object.entries(investigation.security_assessment.security_headers).map(([key, val]) => (
                        <div key={key} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                          <span className="text-cyan-400 font-semibold">{key}:</span>
                          <p className="text-slate-300 truncate">{String(val)}</p>
                        </div>
                      ))}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-2">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 uppercase font-bold block text-[10px]">robots.txt Status</span>
                        <span className="font-mono text-slate-200">{investigation.security_assessment.robots_txt_status}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 uppercase font-bold block text-[10px]">security.txt (RFC 9116)</span>
                        <span className="font-mono text-slate-200">{investigation.security_assessment.security_txt_status}</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Security assessment not available.</p>
                )}
              </div>
            )}

            {/* Tab 5: Threat Feeds */}
            {activeTab === 'feeds' && (
              <div className="space-y-3">
                {investigation.threat_intel_matches.map((feed, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-4 rounded-xl border border-slate-800 bg-slate-900/60"
                  >
                    <div className="space-y-0.5">
                      <h4 className="text-xs font-semibold text-white">{feed.source}</h4>
                      <p className="text-[11px] font-mono text-slate-400">
                        Verdict: <strong className={feed.is_match ? 'text-rose-400' : 'text-slate-300'}>{feed.verdict}</strong> • Confidence: {feed.confidence}
                      </p>
                    </div>
                    <span className={`text-[11px] font-mono px-2 py-1 rounded border font-semibold ${
                      !feed.is_available
                        ? 'bg-slate-900 text-slate-500 border-slate-800'
                        : feed.is_match
                        ? 'bg-rose-950 text-rose-300 border-rose-800'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                    }`}>
                      {feed.is_available ? (feed.is_match ? 'MATCH (MALICIOUS)' : 'NO RECORD') : 'UNAVAILABLE'}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* Tab 6: Raw Evidence */}
            {activeTab === 'raw' && (
              <div className="space-y-4">
                <EvidencePanel title="Canonical Investigation Record" data={investigation} defaultExpanded={true} />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
