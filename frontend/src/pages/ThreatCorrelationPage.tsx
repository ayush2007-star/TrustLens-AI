import React, { useState, useEffect } from 'react';
import {
  Network,
  Share2,
  Server,
  Globe,
  Radio,
  Info,
  ShieldAlert,
  Layers,
  RefreshCw
} from 'lucide-react';
import { apiClient } from '../api/client';
import { ThreatCorrelationGraph, ThreatGraphNode } from '../types';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';

export const ThreatCorrelationPage: React.FC = () => {
  const [graphData, setGraphData] = useState<ThreatCorrelationGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<ThreatGraphNode | null>(null);

  const fetchGraph = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getThreatRelationships();
      setGraphData(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to generate correlation network.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  const getNodeColor = (type: string, risk?: string) => {
    if (type === 'DOMAIN') {
      if (risk === 'HIGH RISK' || risk === 'CONFIRMED MALICIOUS') return '#EF4444';
      if (risk === 'SUSPICIOUS') return '#F59E0B';
      return '#3B82F6';
    }
    if (type === 'IP') return '#06B6D4';
    if (type === 'NAMESERVER') return '#8B5CF6';
    if (type === 'REPORT') return '#EC4899';
    return '#64748B';
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
            <Network className="w-6 h-6 text-cyan-400" />
            Threat Correlation & Infrastructure Topology
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic discovery of shared IP hosting, authoritative nameservers, and direct report-to-domain relationships.
          </p>
        </div>
        <button
          onClick={fetchGraph}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-xs font-semibold text-slate-300 hover:text-white transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Re-compute Topology</span>
        </button>
      </div>

      {/* Methodological Transparency Callout */}
      <div className="rounded-xl border border-purple-500/30 bg-purple-950/20 p-4 space-y-1">
        <div className="flex items-center gap-2 text-purple-300 font-bold text-xs uppercase tracking-wider">
          <Info className="w-4 h-4 text-purple-400" />
          <span>Evidence-Backed Correlation Policy</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Every connection displayed is backed by concrete DNS A-records, authoritative nameserver delegations, or direct incident references. <strong>TrustLens strictly avoids presenting heuristic similarity as proof of a common attacker or single adversary.</strong>
        </p>
      </div>

      {loading && <LoadingSkeleton rows={4} height="h-32" />}
      {error && !loading && <ErrorState message={error} onRetry={fetchGraph} />}

      {graphData && !loading && (
        <div className="space-y-6">
          {/* Topology Metric Highlights */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
              <span className="text-2xl font-bold font-mono text-cyan-400">{graphData.summary.total_nodes}</span>
              <p className="text-xs text-slate-400 mt-1 uppercase font-semibold">Tracked Infrastructure Nodes</p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
              <span className="text-2xl font-bold font-mono text-purple-400">{graphData.summary.total_edges}</span>
              <p className="text-xs text-slate-400 mt-1 uppercase font-semibold">Observed Relationships</p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
              <span className="text-2xl font-bold font-mono text-amber-400">
                {graphData.summary.shared_infrastructure_clusters}
              </span>
              <p className="text-xs text-slate-400 mt-1 uppercase font-semibold">Shared Infrastructure Links</p>
            </div>
          </div>

          {/* Interactive Topology Graph Visualizer */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Visual Canvas Panel */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  Infrastructure Graph
                </span>
                {/* Node Type Legend */}
                <div className="flex items-center gap-3 text-[11px] font-mono">
                  <span className="flex items-center gap-1 text-blue-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Domain
                  </span>
                  <span className="flex items-center gap-1 text-cyan-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" /> IP Host
                  </span>
                  <span className="flex items-center gap-1 text-purple-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-purple-500" /> Nameserver
                  </span>
                  <span className="flex items-center gap-1 text-pink-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-pink-500" /> Report
                  </span>
                </div>
              </div>

              {/* Dynamic SVG Topology View */}
              <div className="relative h-96 w-full rounded-lg bg-slate-900/40 border border-slate-900 overflow-hidden flex items-center justify-center">
                {graphData.nodes.length === 0 ? (
                  <p className="text-xs text-slate-500">No infrastructure correlations recorded yet.</p>
                ) : (
                  <svg className="w-full h-full" viewBox="0 0 600 360">
                    {/* Render Edges */}
                    {graphData.edges.slice(0, 30).map((edge, idx) => {
                      // Generate circular orbit layout
                      const sIdx = graphData.nodes.findIndex((n) => n.id === edge.source);
                      const tIdx = graphData.nodes.findIndex((n) => n.id === edge.target);
                      const total = graphData.nodes.length || 1;

                      const angle1 = (sIdx / total) * 2 * Math.PI;
                      const angle2 = (tIdx / total) * 2 * Math.PI;

                      const x1 = 300 + 190 * Math.cos(angle1);
                      const y1 = 180 + 130 * Math.sin(angle1);
                      const x2 = 300 + 190 * Math.cos(angle2);
                      const y2 = 180 + 130 * Math.sin(angle2);

                      return (
                        <line
                          key={idx}
                          x1={x1}
                          y1={y1}
                          x2={x2}
                          y2={y2}
                          stroke="#334155"
                          strokeWidth="1.5"
                          strokeDasharray={edge.relationship === 'SHARED_HOSTING_IP' ? '4 2' : 'none'}
                          className="opacity-60 hover:opacity-100 transition"
                        />
                      );
                    })}

                    {/* Render Nodes */}
                    {graphData.nodes.slice(0, 30).map((node, idx) => {
                      const total = graphData.nodes.length || 1;
                      const angle = (idx / total) * 2 * Math.PI;
                      const cx = 300 + 190 * Math.cos(angle);
                      const cy = 180 + 130 * Math.sin(angle);
                      const color = getNodeColor(node.type, node.risk);
                      const isSelected = selectedNode?.id === node.id;

                      return (
                        <g
                          key={node.id}
                          className="cursor-pointer transition-transform hover:scale-125"
                          onClick={() => setSelectedNode(node)}
                        >
                          <circle
                            cx={cx}
                            cy={cy}
                            r={isSelected ? 10 : 7}
                            fill={color}
                            stroke={isSelected ? '#FFFFFF' : '#0B0F19'}
                            strokeWidth="2"
                            className="shadow-md"
                          />
                          <text
                            x={cx}
                            y={cy - 12}
                            textAnchor="middle"
                            fill="#94A3B8"
                            fontSize="9"
                            fontFamily="monospace"
                            className="pointer-events-none select-none"
                          >
                            {node.label.length > 16 ? node.label.slice(0, 14) + '..' : node.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                )}
              </div>
              <p className="text-[11px] text-slate-500 text-center font-mono">
                Click any node to inspect connected infrastructure evidence.
              </p>
            </div>

            {/* Selected Node Details Panel */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Node Forensic Details
              </h3>

              {selectedNode ? (
                <div className="space-y-4 text-xs font-mono animate-fadeIn">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Identifier</span>
                    <p className="text-cyan-300 font-bold break-all">{selectedNode.label}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Category</span>
                    <p className="text-slate-200">{selectedNode.type}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Evaluated Risk</span>
                    <p className="text-slate-200">{selectedNode.risk}</p>
                  </div>

                  {/* Connected relationships */}
                  <div className="space-y-2 pt-2">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">
                      Active Connections:
                    </span>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {graphData.edges
                        .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                        .map((edge, i) => (
                          <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[11px]">
                            <span className="text-cyan-400 font-bold block">{edge.relationship}</span>
                            <span className="text-slate-400">{edge.evidence}</span>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                  Select a node on the topology map to inspect associated telemetry and evidence.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
