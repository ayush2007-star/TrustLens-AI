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
          The presence of a padlock icon or valid TLS certificate merely confirms that data between the user's browser and the remote server is encrypted in transit and that the domain registrant verified domain ownership at issuance time. <strong>Over 80% of modern phishing websites operate over valid, free TLS certificates.</strong> TrustLens AI treats HTTPS strictly as a transport security parameter, not proof of organizational trustworthiness.
        </p>
      </section>

      {/* Axiom 2: Absence of Threat Intel */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-amber-400 font-bold text-sm uppercase tracking-wider">
          <AlertTriangle className="w-5 h-5" />
          <span>Axiom 2: Absence of Known Threats Does Not Imply Safety</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          Adversaries deploy disposable, fast-flux domains and targeted lures that typically remain unlisted by global blacklists for the first 24–72 hours of an active campaign. TrustLens AI never marks a domain "Safe" solely because external threat intelligence APIs returned zero matching records.
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
          When accepting arbitrary URLs, web scanners risk attacking internal cloud networks. TrustLens AI resolves all hostnames prior to connection and blocks loopback (<code>127.0.0.0/8</code>, <code>::1</code>), RFC 1918 private subnets (<code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code>), cloud link-local metadata (<code>169.254.169.254</code>), multicast, and documentation networks. Every step of a redirect chain is independently re-validated.
        </p>
      </section>

      {/* Axiom 5: Cryptographic Ledger */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
        <div className="flex items-center gap-2 text-purple-400 font-bold text-sm uppercase tracking-wider">
          <FileCheck2 className="w-5 h-5" />
          <span>Axiom 5: Content Integrity vs Claim Validity</span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          The tamper-evident cryptographic registry implements SHA-256 hash chaining to prove mathematical non-repudiation (guaranteeing that a recorded threat report cannot be modified or deleted by unauthorized database admins). <strong>However, the hash chain proves integrity of the recorded content, not that the submitter's original claim was factually true.</strong>
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
            <p>abuse.ch URLhaus, PhishTank, dnspython, cryptography</p>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase font-bold block text-[10px]">Smart Contract Demonstrator</span>
            <p>Solidity ^0.8.20 (<code>contracts/TrustLensRegistry.sol</code>)</p>
          </div>
        </div>
      </section>
    </div>
  );
};
