export type RiskLevel = 
  | 'LOW RISK'
  | 'SUSPICIOUS'
  | 'HIGH RISK'
  | 'CONFIRMED MALICIOUS'
  | 'INCONCLUSIVE';

export type SeverityLevel = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface URLFinding {
  category: string;
  finding_title: string;
  severity: SeverityLevel;
  evidence: string;
  impact?: string;
  remediation?: string;
}

export interface DomainInformation {
  domain: string;
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  age_days?: number;
  nameservers: string[];
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  txt_records: string[];
  suspicious_dns_flags: string[];
  raw_details?: Record<string, any>;
}

export interface TLSReport {
  is_valid: boolean;
  status_text: string;
  not_before?: string;
  not_after?: string;
  days_remaining?: number;
  subject: Record<string, any>;
  issuer: Record<string, any>;
  san_list: string[];
  signature_algorithm?: string;
  key_type?: string;
  key_size?: number;
  tls_version?: string;
  hostname_match: boolean;
  connection_errors: string[];
  chain_info: any[];
  limitation_notes?: string;
}

export interface SecurityAssessment {
  https_available: boolean;
  http_status?: number;
  security_headers: Record<string, any>;
  cookies: any[];
  robots_txt_status: string;
  security_txt_status: string;
  passive_findings: Array<{
    title: string;
    severity: SeverityLevel;
    evidence: string;
    impact?: string;
    remediation?: string;
  }>;
  limitations: string[];
}

export interface ThreatIntelMatch {
  source: string;
  is_available: boolean;
  is_match: boolean;
  verdict: string;
  confidence: string;
  details: Record<string, any>;
  checked_at?: string;
}

export interface Investigation {
  id: string;
  target_url: string;
  normalized_url: string;
  hostname: string;
  domain: string;
  ip_address?: string;
  overall_risk: RiskLevel;
  risk_score: number;
  confidence: string;
  summary: string;
  analysis_limitations: string[];
  is_synthetic_demo: boolean;
  status: string;
  created_at: string;
  domain_info?: DomainInformation;
  findings: URLFinding[];
  tls_report?: TLSReport;
  security_assessment?: SecurityAssessment;
  threat_intel_matches: ThreatIntelMatch[];
}

export interface InvestigationSummary {
  id: string;
  target_url: string;
  hostname: string;
  domain: string;
  overall_risk: RiskLevel;
  risk_score: number;
  confidence: string;
  summary: string;
  is_synthetic_demo: boolean;
  created_at: string;
}

export interface DetectedIndicator {
  category: string;
  title: string;
  severity: SeverityLevel;
  evidence_snippet: string;
  reasoning: string;
}

export interface MessageAnalysisResponse {
  id: string;
  risk_level: RiskLevel;
  risk_score: number;
  confidence: string;
  analyzed_via: string;
  summary: string;
  indicators: DetectedIndicator[];
  explanation: string;
  recommended_precautions: string[];
  limitations: string[];
  created_at: string;
}

export interface ThreatReport {
  id: string;
  target_url: string;
  domain: string;
  report_type: string;
  severity: SeverityLevel;
  description: string;
  evidence_reference?: string;
  reporter_alias: string;
  verification_status: string;
  upvotes: number;
  fingerprint?: string;
  registered_in_registry: boolean;
  registry_index?: number;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface RegistryEntry {
  id: string;
  block_index: number;
  report_id: string;
  data_hash: string;
  previous_hash: string;
  chained_hash: string;
  canonical_payload: string;
  registered_at: string;
  reporter_alias: string;
  target_domain: string;
  report_type: string;
}

export interface RegistryVerification {
  report_id: string;
  is_registered: boolean;
  is_tampered: boolean;
  status: 'VERIFIED_AUTHENTIC' | 'TAMPER_DETECTED' | 'NOT_REGISTERED' | 'NOT_FOUND';
  block_index?: number;
  stored_data_hash?: string;
  computed_data_hash?: string;
  stored_chained_hash?: string;
  computed_chained_hash?: string;
  previous_hash?: string;
  registered_at?: string;
  details: string;
}

export interface DashboardStats {
  total_investigations: number;
  high_risk_investigations: number;
  confirmed_malicious_reports: number;
  suspicious_reports: number;
  threat_distribution: Array<{ category: string; count: number }>;
  risk_distribution: Array<{ name: string; value: number }>;
  recent_investigations: InvestigationSummary[];
  recent_reports: ThreatReport[];
  verified_registry_blocks: number;
}

export interface ThreatGraphNode {
  id: string;
  label: string;
  type: 'DOMAIN' | 'IP' | 'NAMESERVER' | 'REPORT' | 'BRAND';
  risk: string;
  details?: Record<string, any>;
}

export interface ThreatGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  evidence: string;
}

export interface ThreatCorrelationGraph {
  nodes: ThreatGraphNode[];
  edges: ThreatGraphEdge[];
  summary: {
    total_nodes: number;
    total_edges: number;
    shared_infrastructure_clusters: number;
  };
}
