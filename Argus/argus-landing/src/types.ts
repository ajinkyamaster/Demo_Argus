/* ═══════════════════════════════════
   TypeScript interfaces for Argus
   ═══════════════════════════════════ */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface PatchCode {
  vulnerable_snippet: string;
  fixed_snippet: string;
  language: string;
  file_path: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  cvss_score: number;
  cve_ids: string[];
  affected_component: string;
  description: string;
  patch_code: PatchCode | null;
}

export interface AgentLog {
  agent: string;
  message: string;
  timestamp: string;
}

export interface ScanSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_duration: string;
  max_cvss: number;
}

export interface BlockchainAnchor {
  tx_hash: string;
  block_number: number;
  timestamp: string;
  report_hash: string;
}

export interface ScanResult {
  scan_id: string;
  target: string;
  timestamp: string;
  status: string;
  summary: ScanSummary;
  vulnerabilities: Vulnerability[];
  agent_logs: AgentLog[];
  blockchain: BlockchainAnchor;
}

export type AgentName = 'Recon' | 'Web Exploiter' | 'Net Exploiter' | 'CVE Engine' | 'Chainer' | 'Report';

export type AgentStatus = 'waiting' | 'active' | 'done' | 'error';

export interface AgentStep {
  name: AgentName;
  label: string;
  color: string;
  status: AgentStatus;
  elapsed?: string;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: 'var(--red)',
  HIGH: 'var(--amber)',
  MEDIUM: 'var(--blue)',
  LOW: 'var(--green)',
};
