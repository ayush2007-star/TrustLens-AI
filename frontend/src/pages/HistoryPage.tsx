import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History,
  Search,
  Filter,
  ArrowRight,
  Calendar,
  ExternalLink,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import { apiClient } from '../api/client';
import { InvestigationSummary } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';

export const HistoryPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const navigate = useNavigate();

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.listInvestigations({
        risk: riskFilter || undefined,
        search: searchTerm || undefined,
        limit: 100
      });
      setInvestigations(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [riskFilter, searchTerm]);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
            <History className="w-6 h-6 text-cyan-400" />
            Investigation History & Audit Trail
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete historical log of all website threat scans and digital trust evaluations.
          </p>
        </div>
        <button
          onClick={fetchHistory}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-xs font-semibold text-slate-300 hover:text-white transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/60">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search domain or URL..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Risk Classifications</option>
            <option value="LOW RISK">LOW RISK</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="HIGH RISK">HIGH RISK</option>
            <option value="CONFIRMED MALICIOUS">CONFIRMED MALICIOUS</option>
            <option value="INCONCLUSIVE">INCONCLUSIVE</option>
          </select>
        </div>
      </div>

      {loading && <LoadingSkeleton rows={6} height="h-20" />}
      {error && !loading && <ErrorState message={error} onRetry={fetchHistory} />}

      {/* History Table */}
      {!loading && !error && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl p-5 space-y-4">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2.5 px-3">Target Hostname</th>
                  <th className="py-2.5 px-3">Risk Classification</th>
                  <th className="py-2.5 px-3">Threat Score</th>
                  <th className="py-2.5 px-3">Summary Diagnostic</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {investigations.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                      No investigation history matching filters.
                    </td>
                  </tr>
                ) : (
                  investigations.map((inv) => (
                    <tr
                      key={inv.id}
                      onClick={() => navigate(`/investigations/${inv.id}`)}
                      className="hover:bg-slate-800/40 cursor-pointer transition"
                    >
                      <td className="py-3 px-3 font-bold text-white max-w-xs truncate">
                        {inv.hostname}
                      </td>
                      <td className="py-3 px-3">
                        <RiskBadge level={inv.overall_risk} size="sm" />
                      </td>
                      <td className="py-3 px-3">
                        <span className="font-bold text-slate-200">{inv.risk_score}/100</span>
                      </td>
                      <td className="py-3 px-3 max-w-sm truncate text-slate-400 font-sans text-[11px]">
                        {inv.summary}
                      </td>
                      <td className="py-3 px-3 text-slate-400 text-[11px]">
                        {new Date(inv.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <span className="text-cyan-400 hover:underline flex items-center justify-end gap-1 font-sans text-[11px] font-semibold">
                          <span>Report</span>
                          <ArrowRight className="w-3 h-3" />
                        </span>
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
