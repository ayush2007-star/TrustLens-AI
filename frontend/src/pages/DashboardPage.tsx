import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Activity,
  FileCheck2,
  Skull,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { apiClient } from '../api/client';
import { DashboardStats, InvestigationSummary, ThreatReport } from '../types';
import { MetricCard } from '../components/MetricCard';
import { RiskBadge } from '../components/RiskBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';

const RISK_COLORS: Record<string, string> = {
  'LOW RISK': '#10B981',
  'SUSPICIOUS': '#F59E0B',
  'HIGH RISK': '#EF4444',
  'CONFIRMED MALICIOUS': '#DC2626',
  'INCONCLUSIVE': '#64748B'
};

const THREAT_COLORS = ['#06B6D4', '#3B82F6', '#8B5CF6', '#EC4899', '#F97316'];

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [quickUrl, setQuickUrl] = useState('');
  const navigate = useNavigate();

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getDashboardStats();
      setStats(data);
    } catch (err: any) {
      setError(err?.response?.data?.message || err.message || 'Failed to load telemetry stats.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickUrl.trim()) {
      navigate(`/investigate?target=${encodeURIComponent(quickUrl.trim())}`);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <div className="h-8 w-48 bg-slate-800 rounded animate-pulse" />
        </div>
        <LoadingSkeleton rows={4} height="h-28" />
      </div>
    );
  }

  if (error || !stats) {
    return <ErrorState message={error || 'Unable to connect to security database'} onRetry={fetchStats} />;
  }

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" />
            Security Intelligence Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Counts reflect stored investigations and reports; registry blocks are counted only while the stored hash chain verifies.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchStats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-xs font-semibold text-slate-300 hover:text-white transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* Quick Launch Action Bar */}
      <form onSubmit={handleQuickScan} className="p-4 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 shadow-xl">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              placeholder="Quick investigate: enter URL or domain..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            className="w-full sm:w-auto px-5 py-2 text-xs font-bold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition whitespace-nowrap shadow-md shadow-cyan-950/40"
          >
            Investigate URL
          </button>
        </div>
      </form>

      {/* Top Telemetry Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Investigations"
          value={stats.total_investigations}
          subtitle="All recorded scans"
          icon={Search}
          variant="blue"
        />
        <MetricCard
          title="High Risk Targets"
          value={stats.high_risk_investigations}
          subtitle="Severe threat anomalies"
          icon={ShieldAlert}
          variant="red"
        />
        <MetricCard
          title="Suspicious Reports"
          value={stats.suspicious_reports}
          subtitle="Under observation"
          icon={AlertTriangle}
          variant="amber"
        />
        <MetricCard
          title="Verified Registry Blocks"
          value={stats.verified_registry_blocks}
          subtitle="Cryptographically chained"
          icon={FileCheck2}
          variant="cyan"
        />
      </div>

      {/* Visual Analytics & Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Chart */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Risk Classification Distribution</h3>
            <span className="text-[11px] font-mono text-slate-400">Database Breakdown</span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={stats.risk_distribution}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                >
                  {stats.risk_distribution.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={RISK_COLORS[entry.name] || THREAT_COLORS[index % THREAT_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1F2937', borderRadius: '0.5rem', fontSize: '12px' }}
                  itemStyle={{ color: '#F9FAFB' }}
                />
                <Legend
                  formatter={(val) => <span className="text-xs text-slate-300">{val}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Categories Breakdown */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Detected Threat Vector Categories</h3>
            <span className="text-[11px] font-mono text-slate-400">Heuristics & Community</span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.threat_distribution} layout="vertical" margin={{ left: 20, right: 20 }}>
                <XAxis type="number" stroke="#64748B" fontSize={11} />
                <YAxis dataKey="category" type="category" stroke="#94A3B8" fontSize={11} width={100} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1F2937', borderRadius: '0.5rem', fontSize: '12px' }}
                  itemStyle={{ color: '#06B6D4' }}
                />
                <Bar dataKey="count" fill="#06B6D4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Split Lists: Recent Investigations & Recent Community Reports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Investigations */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Recent URL Investigations</h3>
            <button
              onClick={() => navigate('/history')}
              className="text-xs font-semibold text-cyan-400 hover:underline flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2">
            {stats.recent_investigations.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">No investigations recorded yet.</p>
            ) : (
              stats.recent_investigations.map((inv) => (
                <div
                  key={inv.id}
                  onClick={() => navigate(`/investigations/${inv.id}`)}
                  className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition"
                >
                  <div className="space-y-0.5 max-w-[65%]">
                    <p className="text-xs font-semibold text-white truncate font-mono">
                      {inv.hostname}
                    </p>
                    <p className="text-[11px] text-slate-400 truncate">
                      {inv.summary}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <RiskBadge level={inv.overall_risk} size="sm" />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recent Community Threat Reports */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Recent Collaborative Threat Reports</h3>
            <button
              onClick={() => navigate('/threat-intel')}
              className="text-xs font-semibold text-cyan-400 hover:underline flex items-center gap-1"
            >
              <span>Intel Center</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2">
            {stats.recent_reports.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">No community reports submitted yet.</p>
            ) : (
              stats.recent_reports.map((rep) => (
                <div
                  key={rep.id}
                  onClick={() => navigate('/threat-intel')}
                  className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition"
                >
                  <div className="space-y-0.5 max-w-[65%]">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-white font-mono">{rep.domain}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 uppercase">
                        {rep.report_type}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate">{rep.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-medium text-cyan-400">
                      {rep.registered_in_registry ? '⛓️ Block #' + rep.registry_index : 'Unregistered'}
                    </span>
                    <RiskBadge level={rep.severity} size="sm" />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
