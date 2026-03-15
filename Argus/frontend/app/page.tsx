"use client";

/**
 * Project Argus — Main Page
 * Person 4 (Frontend) owns everything under /frontend.
 * The API contract is defined in IMPLEMENTATION.md — build against that, not against the backend devs.
 */

import { useState } from "react";
import { BlockchainAnchor } from "./components/BlockchainAnchor";

// ── Types (mirror of backend/models.py) ─────────────────────────────────────

type ScanMode = "quick" | "full" | "focused";
type Module = "sqli" | "xss" | "auth" | "idor" | "csrf" | "path_traversal";
type Severity = "critical" | "high" | "medium" | "low" | "info";
type ScanStatus = "complete" | "running" | "failed";

interface ScanRequest {
  target_url: string;
  scan_mode: ScanMode;
  modules: Module[];
  options: { depth: number; timeout: number; verbose: boolean };
}

interface Vulnerability {
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

interface ScanReport {
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
  agent_logs: { agent: string; timestamp: string; action: string; result: string }[];
}

// ── Hardcoded stub — use this while backend is not ready ─────────────────────

const STUB_REPORT: ScanReport = {
  scan_id: "00000000-0000-0000-0000-000000000000",
  timestamp: new Date().toISOString(),
  target: "http://localhost:5000",
  status: "complete",
  summary: { total_vulnerabilities: 3, critical: 1, high: 1, medium: 1, low: 0, info: 0 },
  vulnerabilities: [
    {
      id: "vuln-1",
      type: "SQL_INJECTION",
      severity: "critical",
      title: "SQL Injection in /api/login",
      description: "Username field is passed directly into a raw SQL query.",
      endpoint: "/api/login",
      method: "POST",
      payload: "' OR '1'='1",
      evidence: "Returned 200 with admin token on crafted payload.",
      remediation: "Use parameterised queries or an ORM.",
      cvss_score: 9.8,
      agent: "SQLiAgent",
    },
    {
      id: "vuln-2",
      type: "IDOR",
      severity: "high",
      title: "IDOR on /api/users/:id",
      description: "No ownership check — any token can fetch any user record.",
      endpoint: "/api/users/2",
      method: "GET",
      payload: null,
      evidence: "User 1 retrieved User 2's PII without error.",
      remediation: "Enforce ownership check server-side on every request.",
      cvss_score: 7.5,
      agent: "AuthAgent",
    },
    {
      id: "vuln-3",
      type: "XSS",
      severity: "medium",
      title: "Reflected XSS in /api/search",
      description: "?q= parameter echoed unsanitised into HTML response.",
      endpoint: "/api/search?q=<script>alert(1)</script>",
      method: "GET",
      payload: "<script>alert(1)</script>",
      evidence: "Script executed in browser.",
      remediation: "HTML-encode all user-controlled output.",
      cvss_score: 6.1,
      agent: "XSSAgent",
    },
  ],
  agent_logs: [
    {
      agent: "ReconAgent",
      timestamp: new Date().toISOString(),
      action: "Endpoint enumeration",
      result: "Discovered: /api/login, /api/users/:id, /api/search, /api/characters",
    },
  ],
};

// ── Severity badge ────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-zinc-500 text-white",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-bold uppercase ${SEVERITY_COLORS[severity]}`}>
      {severity}
    </span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Home() {
  const [targetUrl, setTargetUrl] = useState("http://localhost:5000");
  const [scanMode, setScanMode] = useState<ScanMode>("full");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [useStub, setUseStub] = useState(true);

  async function handleScan() {
    setLoading(true);
    setError(null);
    setReport(null);

    if (useStub) {
      // Simulate network delay so the UI feels real
      await new Promise((r) => setTimeout(r, 1200));
      setReport(STUB_REPORT);
      setLoading(false);
      return;
    }

    const body: ScanRequest = {
      target_url: targetUrl,
      scan_mode: scanMode,
      modules: ["sqli", "xss", "auth", "idor"],
      options: { depth: 3, timeout: 30, verbose: false },
    };

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) throw new Error(`Backend returned ${res.status}`);
      const data: ScanReport = await res.json();
      setReport(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto max-w-4xl p-8 space-y-8">
      {/* Header */}
      <div className="space-y-1">
        <h1 className="text-3xl font-bold tracking-tight">Project Argus</h1>
        <p className="text-zinc-400 text-sm">Autonomous multi-agent AI pentesting · Local use only</p>
      </div>

      {/* Scan form */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 space-y-4">
        <h2 className="text-lg font-semibold">Configure Scan</h2>

        <div className="space-y-2">
          <label className="block text-sm text-zinc-400">Target URL</label>
          <input
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:5000"
          />
        </div>

        <div className="space-y-2">
          <label className="block text-sm text-zinc-400">Scan Mode</label>
          <select
            className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
            value={scanMode}
            onChange={(e) => setScanMode(e.target.value as ScanMode)}
          >
            <option value="quick">Quick</option>
            <option value="full">Full</option>
            <option value="focused">Focused</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <input
            id="stub"
            type="checkbox"
            checked={useStub}
            onChange={(e) => setUseStub(e.target.checked)}
            className="accent-red-500"
          />
          <label htmlFor="stub" className="text-sm text-zinc-400">
            Use stub data (backend not ready yet)
          </label>
        </div>

        <button
          onClick={handleScan}
          disabled={loading}
          className="rounded-lg bg-red-600 px-6 py-2 text-sm font-semibold hover:bg-red-500 disabled:opacity-50 transition-colors"
        >
          {loading ? "Scanning…" : "Launch Scan"}
        </button>
      </section>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Report */}
      {report && (
        <section className="space-y-6">
          {/* Summary */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 space-y-3">
            <h2 className="text-lg font-semibold">Scan Summary</h2>
            <p className="text-xs text-zinc-500">
              {report.scan_id} · {new Date(report.timestamp).toLocaleString()}
            </p>
            <div className="flex gap-4 flex-wrap">
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
                <div key={sev} className="text-center">
                  <div className="text-2xl font-bold">{report.summary[sev]}</div>
                  <SeverityBadge severity={sev} />
                </div>
              ))}
            </div>
          </div>

          {/* PDF Download + Blockchain Anchor */}
          <div className="flex items-center gap-4 flex-wrap">
            <a
              href={`/api/scan/${report.scan_id}/report/pdf`}
              download
              className="inline-flex items-center gap-2 rounded-full border border-zinc-700 bg-zinc-900 px-4 py-2 text-xs font-semibold text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 transition-all"
            >
              Download PDF
            </a>
            <BlockchainAnchor
              scanId={report.scan_id}
              reportJson={JSON.stringify(report)}
            />
          </div>

          {/* Vulnerabilities */}
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">
              Vulnerabilities ({report.summary.total_vulnerabilities})
            </h2>
            {report.vulnerabilities.map((v) => (
              <div key={v.id} className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-2">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={v.severity} />
                  <span className="font-semibold">{v.title}</span>
                  <span className="ml-auto text-xs text-zinc-500">CVSS {v.cvss_score}</span>
                </div>
                <p className="text-sm text-zinc-300">{v.description}</p>
                <div className="text-xs text-zinc-500 space-x-3">
                  <span>{v.method} {v.endpoint}</span>
                  <span>·</span>
                  <span>Agent: {v.agent}</span>
                </div>
                {v.payload && (
                  <code className="block rounded bg-zinc-800 px-3 py-2 text-xs text-green-400">
                    {v.payload}
                  </code>
                )}
                <p className="text-xs text-zinc-400">
                  <span className="font-semibold text-zinc-300">Fix: </span>
                  {v.remediation}
                </p>
              </div>
            ))}
          </div>

          {/* Agent logs */}
          <div className="space-y-2">
            <h2 className="text-lg font-semibold">Agent Logs</h2>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 divide-y divide-zinc-800">
              {report.agent_logs.map((log, i) => (
                <div key={i} className="px-5 py-3 text-sm space-y-0.5">
                  <div className="flex gap-2 text-xs text-zinc-500">
                    <span className="font-mono text-zinc-300">{log.agent}</span>
                    <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="text-zinc-300">{log.action}</div>
                  <div className="text-zinc-500">{log.result}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
