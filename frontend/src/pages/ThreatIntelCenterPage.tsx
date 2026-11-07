import React, { useState, useEffect } from 'react';
import {
  Radio,
  PlusCircle,
  ThumbsUp,
  FileCheck2,
  Filter,
  Search,
  ExternalLink,
  ShieldAlert,
  Clock,
  User,
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import { apiClient } from '../api/client';
import { ThreatReport } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';
import { ConfirmDialog } from '../components/ConfirmDialog';

export const ThreatIntelCenterPage: React.FC = () => {
  const [reports, setReports] = useState<ThreatReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [searchDomain, setSearchDomain] = useState('');
  
  // Modal states
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [registeringId, setRegisteringId] = useState<string | null>(null);
  const [confirmRegisterId, setConfirmRegisterId] = useState<string | null>(null);

  // Form states
  const [formUrl, setFormUrl] = useState('');
  const [formType, setFormType] = useState('PHISHING');
  const [formSeverity, setFormSeverity] = useState('HIGH');
  const [formDescription, setFormDescription] = useState('');
  const [formEvidence, setFormEvidence] = useState('');
  const [formAlias, setFormAlias] = useState('');

  const fetchReports = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.listThreatReports({
        status: statusFilter || undefined,
        domain: searchDomain || undefined
      });
      setReports(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch community threat reports.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [statusFilter, searchDomain]);

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formUrl.trim() || !formDescription.trim()) return;

    setSubmitting(true);
    try {
      await apiClient.createThreatReport({
        target_url: formUrl.trim(),
        report_type: formType,
        severity: formSeverity,
        description: formDescription.trim(),
        evidence_reference: formEvidence.trim() || undefined,
        reporter_alias: formAlias.trim() || undefined,
        tags: [formType.toLowerCase()]
      });
      setShowSubmitModal(false);
      setFormUrl('');
      setFormDescription('');
      setFormEvidence('');
      fetchReports();
    } catch (err: any) {
      alert('Error submitting report: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpvote = async (id: string) => {
    try {
      const updated = await apiClient.upvoteThreatReport(id);
      setReports((prev) =>
        prev.map((r) => (r.id === id ? { ...r, upvotes: updated.upvotes, verification_status: updated.status } : r))
      );
    } catch (err) {
      console.error(err);
    }
  };

  const handleRegisterOnChain = async (id: string) => {
    try {
      setRegisteringId(id);
      await apiClient.registerReportOnChain(id);
      fetchReports();
    } catch (err: any) {
      alert('Registration error: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setRegisteringId(null);
      setConfirmRegisterId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
            <Radio className="w-6 h-6 text-cyan-400" />
            Collaborative Threat Intelligence Center
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Crowdsourced community threat submissions with researcher corroboration and cryptographic ledger anchoring.
          </p>
        </div>
        <button
          onClick={() => setShowSubmitModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-lg shadow-cyan-950/40"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Submit Threat Report</span>
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/60">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchDomain}
            onChange={(e) => setSearchDomain(e.target.value)}
            placeholder="Search domain or keyword..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Verification Statuses</option>
            <option value="Pending">Pending</option>
            <option value="Under Review">Under Review</option>
            <option value="Supported by Evidence">Supported by Evidence</option>
            <option value="Disputed">Disputed</option>
            <option value="Rejected">Rejected</option>
          </select>
        </div>
      </div>

      {loading && <LoadingSkeleton rows={5} height="h-28" />}
      {error && !loading && <ErrorState message={error} onRetry={fetchReports} />}

      {/* Reports Feed */}
      {!loading && !error && (
        <div className="space-y-4">
          {reports.length === 0 ? (
            <div className="p-12 text-center rounded-xl border border-dashed border-slate-800 bg-slate-900/30 text-xs text-slate-500">
              No threat reports match your filter criteria.
            </div>
          ) : (
            reports.map((report) => (
              <div
                key={report.id}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 hover:border-slate-700 transition"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-bold font-mono text-white">{report.domain}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                        {report.report_type}
                      </span>
                      <RiskBadge level={report.severity} size="sm" />
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        Status: <strong>{report.verification_status}</strong>
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-400 truncate break-all">
                      {report.target_url}
                    </p>
                  </div>

                  {/* Actions & Ledger Status */}
                  <div className="flex items-center gap-3 shrink-0">
                    <button
                      onClick={() => handleUpvote(report.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-xs text-slate-200 transition"
                      title="Corroborate this report"
                    >
                      <ThumbsUp className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{report.upvotes}</span>
                    </button>

                    {report.registered_in_registry ? (
                      <span className="flex items-center gap-1 text-xs font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-500/40 px-2.5 py-1 rounded-lg">
                        <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Block #{report.registry_index}</span>
                      </span>
                    ) : (
                      <button
                        onClick={() => setConfirmRegisterId(report.id)}
                        disabled={registeringId === report.id}
                        className="flex items-center gap-1 text-xs font-semibold px-2.5 py-1 rounded-lg bg-blue-950 hover:bg-blue-900 border border-blue-500/30 text-blue-300 transition"
                      >
                        <FileCheck2 className="w-3.5 h-3.5" />
                        <span>{registeringId === report.id ? 'Anchoring...' : 'Register on Ledger'}</span>
                      </button>
                    )}
                  </div>
                </div>

                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                  {report.description}
                </p>

                {report.evidence_reference && (
                  <div className="p-2.5 rounded bg-slate-950 font-mono text-xs text-slate-400 border border-slate-800/80 break-all">
                    <span className="text-slate-500 font-bold block text-[10px] uppercase mb-0.5">Evidence Reference:</span>
                    {report.evidence_reference}
                  </div>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 text-[11px] text-slate-500 font-mono">
                  <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1">
                      <User className="w-3 h-3" />
                      {report.reporter_alias}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(report.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  {report.fingerprint && (
                    <span className="truncate max-w-xs text-slate-400">
                      Fingerprint: {report.fingerprint.slice(0, 16)}...
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Submit Report Modal */}
      {showSubmitModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Radio className="w-5 h-5 text-cyan-400" />
              Submit Collaborative Threat Report
            </h3>

            <form onSubmit={handleCreateReport} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">Target URL or Domain *</label>
                <input
                  type="text"
                  required
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder="https://scam-site.example.com/login"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Threat Classification</label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="PHISHING">PHISHING</option>
                    <option value="IMPERSONATION">IMPERSONATION</option>
                    <option value="MALWARE">MALWARE</option>
                    <option value="SCAM_MESSAGE">SCAM_MESSAGE</option>
                    <option value="FAKE_PORTAL">FAKE_PORTAL</option>
                    <option value="OTHER">OTHER</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Description & Threat Narrative *</label>
                <textarea
                  required
                  rows={3}
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Detailed findings: fake branding, deceptive credential form, SMS campaign..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Evidence Reference (Optional)</label>
                <input
                  type="text"
                  value={formEvidence}
                  onChange={(e) => setFormEvidence(e.target.value)}
                  placeholder="SHA-256 hash, URLhaus ID, or DNS anomaly..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Researcher Alias (Optional)</label>
                <input
                  type="text"
                  value={formAlias}
                  onChange={(e) => setFormAlias(e.target.value)}
                  placeholder="Anonymous Researcher or Handle"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowSubmitModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
                >
                  {submitting ? 'Submitting...' : 'Submit Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Dialog for Registering on Ledger */}
      <ConfirmDialog
        isOpen={Boolean(confirmRegisterId)}
        title="Commit to Immutable Trust Ledger?"
        message="Registering this report generates a canonical SHA-256 fingerprint chained to previous blocks in the tamper-evident registry. Once committed, the fingerprint cannot be altered."
        confirmText="Register Fingerprint"
        onConfirm={() => confirmRegisterId && handleRegisterOnChain(confirmRegisterId)}
        onCancel={() => setConfirmRegisterId(null)}
      />
    </div>
  );
};
