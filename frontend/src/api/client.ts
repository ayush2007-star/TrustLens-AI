import axios from 'axios';
import {
  Investigation,
  InvestigationSummary,
  MessageAnalysisResponse,
  ThreatReport,
  RegistryEntry,
  RegistryVerification,
  DashboardStats,
  ThreatCorrelationGraph
} from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

export const apiClient = {
  // Health
  getHealth: async () => {
    const res = await api.get('/health');
    return res.data;
  },

  // Dashboard
  getDashboardStats: async (): Promise<DashboardStats> => {
    const res = await api.get('/dashboard/stats');
    return res.data;
  },

  // URL Investigations
  investigateUrl: async (url: string): Promise<Investigation> => {
    const res = await api.post('/investigations', { url });
    return res.data;
  },

  listInvestigations: async (params?: { risk?: string; search?: string; limit?: number }): Promise<InvestigationSummary[]> => {
    const res = await api.get('/investigations', { params });
    return res.data;
  },

  getInvestigation: async (id: string): Promise<Investigation> => {
    const res = await api.get(`/investigations/${id}`);
    return res.data;
  },

  // Scam Message Analyzer
  analyzeMessage: async (message_text: string): Promise<MessageAnalysisResponse> => {
    const res = await api.post('/analyze-message', { message_text });
    return res.data;
  },

  // Threat Reports
  listThreatReports: async (params?: { status?: string; report_type?: string; domain?: string }): Promise<ThreatReport[]> => {
    const res = await api.get('/threat-reports', { params });
    return res.data;
  },

  createThreatReport: async (data: {
    target_url: string;
    report_type: string;
    severity: string;
    description: string;
    evidence_reference?: string;
    reporter_alias?: string;
    tags?: string[];
  }): Promise<ThreatReport> => {
    const res = await api.post('/threat-reports', data);
    return res.data;
  },

  upvoteThreatReport: async (id: string) => {
    const res = await api.post(`/threat-reports/${id}/upvote`);
    return res.data;
  },

  // Trust Registry
  getRegistryLedger: async (): Promise<RegistryEntry[]> => {
    const res = await api.get('/registry');
    return res.data;
  },

  registerReportOnChain: async (report_id: string): Promise<RegistryEntry> => {
    const res = await api.post('/registry/register', { report_id });
    return res.data;
  },

  verifyRegistryReport: async (report_id: string): Promise<RegistryVerification> => {
    const res = await api.get(`/registry/verify/${report_id}`);
    return res.data;
  },

  // Threat Relationships
  getThreatRelationships: async (): Promise<ThreatCorrelationGraph> => {
    const res = await api.get('/threat-relationships');
    return res.data;
  }
};
