import React from 'react';
import {
  BookOpen,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Network,
  FileCheck2,
  Code,
  ExternalLink,
  Cpu
} from 'lucide-react';

export const MethodologyPage: React.FC = () => {
  return (
    <div className="space-y-10 max-w-4xl mx-auto pb-12">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-5">
        <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white flex items-center gap-2.5">
          <BookOpen className="w-7 h-7 text-cyan-400" />
          Security Methodology & Technical Disclosures
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Forensic architecture, defense-in-depth principles, and transparency guidelines powering TrustLens AI.
        </p>
      </div>

      {/* Axiom 1: HTTPS Fallacy */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm uppercase tracking-wider">
          <Lock className="w-5 h-5" />
          <span>Axiom 1: HTTPS Confirms Encryption, Not Legitimacy</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          A valid TLS certificate helps verify an encrypted connection to a hostname; it does not prove that the site or organization is trustworthy. TrustLens AI treats HTTPS only as a transport-security signal, never as proof of legitimacy.
        </p>
      </section>

      {/* Axiom 2: Absence of Threat Intel */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-amber-400 font-bold text-sm uppercase tracking-wider">
          <AlertTriangle className="w-5 h-5" />
          <span>Axiom 2: Absence of Known Threats Does Not Imply Safety</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          Threat feeds can be incomplete or unavailable. A missing record is not a clean verdict, and TrustLens AI does not infer that a target is safe from an unavailable feed.
        </p>
      </section>

      {/* Axiom 3: Passive Assessment Boundaries */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm uppercase tracking-wider">
          <ShieldCheck className="w-5 h-5" />
          <span>Axiom 3: Strictly Passive, Non-Intrusive Observation</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          TrustLens AI observes ethical security auditing standards. All website security evaluations are conducted passively by inspecting standard HTTP response headers, cookie flags, TLS certificates, and public metadata endpoints (such as RFC 9116 <code>security.txt</code>). <strong>The platform never executes JavaScript, never injects payloads, never attempts authentication bypass, and never performs port scanning.</strong>
        </p>
      </section>

      {/* Axiom 4: SSRF Architecture */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-blue-400 font-bold text-sm uppercase tracking-wider">
          <Network className="w-5 h-5" />
          <span>Axiom 4: Multi-Layer Server-Side Request Forgery (SSRF) Defense</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          Target hostnames are resolved and rejected if any answer is not globally routable or DNS resolution fails. The HTTP and TLS scanners connect to a validated IP address while preserving the original hostname for the HTTP Host header and TLS verification, mitigating DNS rebinding between validation and connection. Redirects are inspected one hop at a time; each destination is revalidated and pinned. Requests have a timeout and bounded response body.
        </p>
      </section>

      {/* Axiom 5: Cryptographic Ledger */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-purple-400 font-bold text-sm uppercase tracking-wider">
          <FileCheck2 className="w-5 h-5" />
          <span>Axiom 5: Content Integrity vs Claim Validity</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          The local database registry stores canonical report hashes linked with SHA-256 and checks the full chain during verification. It can detect inconsistent stored records, but it does not prevent a database administrator from rewriting the entire database and is not an external blockchain or proof of a report's factual accuracy.
        </p>
      </section>

      {/* Technical Disclosures */}
      <section className="rounded-xl border border-slate-800 bg-slate-950 p-6 space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          Technical Stack & Disclosures
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono text-slate-300">
          <div className="space-y-1">
            <span className="text-slate-500 uppercase font-bold block text-[10px]">Backend Framework</span>
            <p>FastAPI (Python 3.13) + Pydantic v2 + SQLAlchemy</p>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase font-bold block text-[10px]">Frontend Architecture</span>
            <p>React 18 + Vite + TypeScript + Tailwind CSS</p>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase font-bold block text-[10px]">Threat Feeds & DNS</span>
            <p>URLhaus (optional live query), VirusTotal (API key), dnspython, cryptography; PhishTank/OpenPhish are not live integrations.</p>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase font-bold block text-[10px]">Smart Contract Demonstrator</span>
            <p>Solidity source demonstrator only; the application does not deploy or call it.</p>
          </div>
        </div>
      </section>
    </div>
  );
};
