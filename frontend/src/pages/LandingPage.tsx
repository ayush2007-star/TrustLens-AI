import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  Shield,
  Lock,
  MessageSquareWarning,
  Network,
  FileCheck2,
  ArrowRight,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  ChevronRight,
  Database
} from 'lucide-react';
import { BrandLogo } from '../components/BrandLogo';
import { apiClient } from '../api/client';
import { DashboardStats } from '../types';

export const LandingPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    apiClient.getDashboardStats()
      .then(setStats)
      .catch(() => {});
  }, []);

  const handleInvestigateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (urlInput.trim()) {
      navigate(`/investigate?target=${encodeURIComponent(urlInput.trim())}`);
    } else {
      navigate('/investigate');
    }
  };

  return (
    <div className="space-y-20 pb-16">
      {/* Hero Section */}
      <section className="relative overflow-hidden pt-12 md:pt-20 text-center">
        {/* Ambient cyber glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-cyan-500/10 blur-[120px] rounded-full pointer-events-none" />

        <div className="max-w-4xl mx-auto px-4 relative z-10 space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 text-xs font-mono font-medium">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>AI-POWERED WEB THREAT & DIGITAL TRUST INTELLIGENCE</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-white leading-tight">
            Know What's Behind <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400">
              Every Link.
            </span>
          </h1>

          <p className="text-base sm:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed">
            Investigate phishing URLs, fraudulent banking replicas, and scam messages.
            Verify TLS certificates, discover deceptive brand typosquatting, and audit threats with an immutable cryptographic ledger.
          </p>

          {/* Quick Investigation Bar */}
          <form onSubmit={handleInvestigateSubmit} className="max-w-2xl mx-auto pt-4">
            <div className="flex flex-col sm:flex-row items-center gap-2 p-2 rounded-xl bg-slate-900 border border-slate-700/80 shadow-2xl focus-within:border-cyan-500 transition">
              <div className="flex items-center gap-3 w-full px-3 py-1">
                <Search className="w-5 h-5 text-cyan-400 shrink-0" />
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="Enter a website URL or domain (e.g., paypal-security-update.example.com)..."
                  className="w-full bg-transparent text-sm text-white placeholder-slate-500 focus:outline-none font-mono"
                />
              </div>
              <div className="flex w-full sm:w-auto gap-2">
                <button
                  type="submit"
                  className="w-full sm:w-auto px-6 py-3 rounded-lg text-xs font-bold uppercase tracking-wider bg-cyan-600 hover:bg-cyan-500 text-white transition whitespace-nowrap shadow-md shadow-cyan-950"
                >
                  Analyze Website
                </button>
              </div>
            </div>
            {/* Quick Demo Pre-fill links */}
            <div className="flex flex-wrap items-center justify-center gap-2 pt-3 text-xs text-slate-400">
              <span>Try benchmark:</span>
              <button
                type="button"
                onClick={() => setUrlInput('https://paypal-security-update.example.com/login?token=urgent')}
                className="text-cyan-400 hover:underline font-mono"
              >
                PayPal Typosquat
              </button>
              <span>•</span>
              <button
                type="button"
                onClick={() => setUrlInput('https://en.wikipedia.org')}
                className="text-cyan-400 hover:underline font-mono"
              >
                Wikipedia (Benign)
              </button>
              <span>•</span>
              <button
                type="button"
                onClick={() => setUrlInput('http://198.51.100.42:8080/banking/verification')}
                className="text-cyan-400 hover:underline font-mono"
              >
                Raw IP Banking
              </button>
            </div>
          </form>

          {/* Secondary Action */}
          <div className="pt-2">
            <button
              onClick={() => navigate('/message-analyzer')}
              className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-cyan-300 transition py-1"
            >
              <MessageSquareWarning className="w-4 h-4 text-purple-400" />
              <span>Or analyze a suspicious SMS, email, or recruitment message</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </section>

      {/* Real Statistics Section - ONLY from DB, NEVER invented */}
      {stats && stats.total_investigations > 0 && (
        <section className="max-w-5xl mx-auto px-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 backdrop-blur-sm">
            <div className="text-center mb-6">
              <span className="text-xs font-mono font-semibold tracking-wider uppercase text-cyan-400">
                Operational Telemetry (Live Database)
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
                <p className="text-2xl sm:text-3xl font-black font-mono text-white">{stats.total_investigations}</p>
                <p className="text-xs text-slate-400 mt-1 uppercase">Investigations</p>
              </div>
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
                <p className="text-2xl sm:text-3xl font-black font-mono text-rose-400">{stats.high_risk_investigations}</p>
                <p className="text-xs text-slate-400 mt-1 uppercase">High Risk URLs</p>
              </div>
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
                <p className="text-2xl sm:text-3xl font-black font-mono text-amber-400">{stats.suspicious_reports}</p>
                <p className="text-xs text-slate-400 mt-1 uppercase">Suspicious Reports</p>
              </div>
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
                <p className="text-2xl sm:text-3xl font-black font-mono text-cyan-400">{stats.verified_registry_blocks}</p>
                <p className="text-xs text-slate-400 mt-1 uppercase">Ledger Blocks</p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Core Security Principle Callout */}
      <section className="max-w-5xl mx-auto px-4">
        <div className="rounded-2xl border border-amber-500/30 bg-gradient-to-r from-amber-950/20 via-slate-900 to-blue-950/20 p-8 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-bold text-white">
              The Digital Trust Fallacy: "HTTPS Does Not Mean Safe"
            </h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            A valid TLS certificate only proves that your connection to the server is encrypted and that the domain registrant verified control of the hostname. <strong>It does not prove the website or business is legitimate.</strong> Over 80% of phishing kits operate over legitimate, free HTTPS certificates.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">What HTTPS Guarantees</h4>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                <li>Traffic is encrypted against local network eavesdropping.</li>
                <li>Data in transit has not been tampered with by man-in-the-middle.</li>
                <li>The server matches the domain listed on the certificate.</li>
              </ul>
            </div>
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wider">What HTTPS Cannot Prove</h4>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                <li>Whether the website is an impersonation or credential harvester.</li>
                <li>Whether the organization behind the domain is authentic.</li>
                <li>Whether the business or payment request is fraudulent.</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Key Platform Capabilities */}
      <section className="max-w-5xl mx-auto px-4 space-y-10">
        <div className="text-center space-y-2">
          <h2 className="text-2xl sm:text-3xl font-bold text-white">Comprehensive Threat Intelligence</h2>
          <p className="text-sm text-slate-400 max-w-xl mx-auto">
            Six interconnected security analysis modules providing complete forensic visibility.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-slate-700 transition">
            <div className="p-3 w-fit rounded-lg bg-blue-950/80 border border-blue-500/30 text-blue-400">
              <Search className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Intelligent URL Heuristics</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Detects brand typosquatting, Punycode/IDN homoglyphs, raw IP hosting, excessive subdomains, and embedded authentication tokens.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-slate-700 transition">
            <div className="p-3 w-fit rounded-lg bg-cyan-950/80 border border-cyan-500/30 text-cyan-400">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">TLS & Digital Trust Analysis</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Real X.509 certificate parsing inspecting SANs, issuer authority, validity dates, key algorithm size, and hostname verification.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-slate-700 transition">
            <div className="p-3 w-fit rounded-lg bg-purple-950/80 border border-purple-500/30 text-purple-400">
              <MessageSquareWarning className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">AI Scam Message Analyzer</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Examines SMS, WhatsApp, and email lures for psychological urgency, OTP solicitation, advance fees, and remote-desktop demands.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-slate-700 transition">
            <div className="p-3 w-fit rounded-lg bg-amber-950/80 border border-amber-500/30 text-amber-400">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Passive Security Assessment</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Non-intrusive evaluation of HSTS, CSP, X-Frame-Options, secure cookies, and RFC 9116 security.txt posture without intrusive exploits.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-slate-700 transition">
            <div className="p-3 w-fit rounded-lg bg-emerald-950/80 border border-emerald-500/30 text-emerald-400">
              <Network className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Threat Correlation Engine</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Correlates shared IP hosting, authoritative nameservers, and brand-targeting patterns across community reports into a visual relationship graph.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-slate-700 transition">
            <div className="p-3 w-fit rounded-lg bg-rose-950/80 border border-rose-500/30 text-rose-400">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Tamper-Evident Ledger</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Append-only SHA-256 hash chaining guarantees collaborative reports cannot be retroactively modified without immediate detection.
            </p>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="max-w-5xl mx-auto px-4 space-y-8">
        <div className="text-center space-y-2">
          <h2 className="text-2xl sm:text-3xl font-bold text-white">How TrustLens AI Investigates</h2>
          <p className="text-sm text-slate-400">Step-by-step forensic evaluation of every submission</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-cyan-400 font-bold">STAGE 01</span>
            <h4 className="text-sm font-semibold text-white">Normalize & Sanitize</h4>
            <p className="text-xs text-slate-400">Validates syntax, enforces SSRF protections, and strips deceptive authority credentials.</p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-blue-400 font-bold">STAGE 02</span>
            <h4 className="text-sm font-semibold text-white">Probe & Trace</h4>
            <p className="text-xs text-slate-400">Safe redirect tracing without executing JS, querying DNS records, and fetching X.509 certs.</p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-purple-400 font-bold">STAGE 03</span>
            <h4 className="text-sm font-semibold text-white">Cross-Reference Feeds</h4>
            <p className="text-xs text-slate-400">Queries URLhaus, PhishTank, OpenPhish, and local heuristic engines.</p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-emerald-400 font-bold">STAGE 04</span>
            <h4 className="text-sm font-semibold text-white">Explainable Risk Score</h4>
            <p className="text-xs text-slate-400">Calculates deterministic 0-100 risk classification backed by concrete evidence.</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="max-w-5xl mx-auto px-4 pt-12 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-white">TRUSTLENS AI</span>
          <span>•</span>
          <span>Hackathon MVP Edition (November 2026)</span>
        </div>
        <div className="flex items-center gap-6">
          <button onClick={() => navigate('/methodology')} className="hover:text-cyan-400 transition">
            Security Methodology
          </button>
          <button onClick={() => navigate('/history')} className="hover:text-cyan-400 transition">
            Investigation History
          </button>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 hover:text-cyan-400 transition"
          >
            <span>Documentation</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </footer>
    </div>
  );
};
