// Shared TypeScript types — mirrors backend/models.py exactly

export type ScanMode = "quick" | "full" | "focused";
export type Module = "sqli" | "xss" | "auth" | "idor" | "csrf" | "path_traversal";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "complete" | "running" | "failed";

export interface ScanRequest {
  target_url: string;
  scan_mode: ScanMode;
  modules: Module[];
  options: {
    depth: number;
    timeout: number;
    verbose: boolean;
  };
}

export interface Vulnerability {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  endpoint: string;
  method: string;
  payload: string | null;
  evidence: string | null;
  remediation: string;
  cvss_score: number;
  agent: string;
}

export interface AgentLog {
  agent: string;
  timestamp: string;
  action: string;
  result: string;
}

export interface ScanReport {
  scan_id: string;
  timestamp: string;
  target: string;
  status: ScanStatus;
  summary: {
    total_vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  vulnerabilities: Vulnerability[];
  agent_logs: AgentLog[];
}

// ── Severity helpers ─────────────────────────────────────────────────────────

export const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; badge: string; bar: string; ring: string; dot: string }
> = {
  critical: {
    label: "Critical",
    badge: "bg-red-600 text-white",
    bar: "bg-red-600",
    ring: "ring-red-600/40",
    dot: "bg-red-500",
  },
  high: {
    label: "High",
    badge: "bg-orange-500 text-white",
    bar: "bg-orange-500",
    ring: "ring-orange-500/40",
    dot: "bg-orange-400",
  },
  medium: {
    label: "Medium",
    badge: "bg-yellow-500 text-black",
    bar: "bg-yellow-500",
    ring: "ring-yellow-500/40",
    dot: "bg-yellow-400",
  },
  low: {
    label: "Low",
    badge: "bg-blue-500 text-white",
    bar: "bg-blue-500",
    ring: "ring-blue-500/40",
    dot: "bg-blue-400",
  },
  info: {
    label: "Info",
    badge: "bg-zinc-500 text-white",
    bar: "bg-zinc-500",
    ring: "ring-zinc-500/40",
    dot: "bg-zinc-400",
  },
};

export const MODULE_META: Record<Module, { label: string; desc: string }> = {
  sqli:           { label: "SQL Injection",    desc: "Detect raw SQL query injection" },
  xss:            { label: "XSS",              desc: "Cross-site scripting vectors" },
  auth:           { label: "Auth Bypass",      desc: "Authentication weaknesses" },
  idor:           { label: "IDOR",             desc: "Insecure direct object refs" },
  csrf:           { label: "CSRF",             desc: "Cross-site request forgery" },
  path_traversal: { label: "Path Traversal",   desc: "Directory traversal attacks" },
};
