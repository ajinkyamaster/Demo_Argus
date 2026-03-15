"use client";

import { CheckCircle2, AlertCircle, Clock } from "lucide-react";
import { ScanReport, Severity, SEVERITY_CONFIG } from "./types";
import { CvssDial } from "./CvssDial";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function riskLabel(report: ScanReport): { label: string; color: string } {
  if (report.summary.critical > 0) return { label: "CRITICAL RISK",  color: "text-red-500" };
  if (report.summary.high > 0)     return { label: "HIGH RISK",      color: "text-orange-400" };
  if (report.summary.medium > 0)   return { label: "MEDIUM RISK",    color: "text-yellow-400" };
  if (report.summary.low > 0)      return { label: "LOW RISK",       color: "text-blue-400" };
  return                                  { label: "CLEAN",          color: "text-green-400" };
}

function riskScore(report: ScanReport): number {
  const { critical, high, medium, low } = report.summary;
  const raw = critical * 9.5 + high * 7.0 + medium * 4.5 + low * 2.0;
  return Math.min(100, Math.round((raw / 30) * 100));
}

export function ScanSummary({ report }: { report: ScanReport }) {
  const risk  = riskLabel(report);
  const score = riskScore(report);
  const total = report.summary.total_vulnerabilities;

  const statusIcon =
    report.status === "complete" ? (
      <CheckCircle2 className="h-4 w-4 text-green-500" />
    ) : report.status === "failed" ? (
      <AlertCircle className="h-4 w-4 text-red-500" />
    ) : (
      <Clock className="h-4 w-4 text-yellow-500" />
    );

  return (
    <section className="space-y-4 animate-fade-in-up">
      {/* Top bar: scan meta */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900 px-6 py-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2">
              {statusIcon}
              <span className="text-sm font-semibold text-zinc-200 capitalize">
                Scan {report.status}
              </span>
            </div>
            <div className="text-xs text-zinc-600 terminal">
              ID: {report.scan_id}
            </div>
          </div>
          <div className="text-right space-y-0.5">
            <div className="text-xs text-zinc-500">Target</div>
            <div className="text-sm font-mono text-zinc-300">{report.target}</div>
          </div>
          <div className="text-right space-y-0.5">
            <div className="text-xs text-zinc-500">Completed</div>
            <div className="text-sm text-zinc-300">
              {new Date(report.timestamp).toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {/* Total */}
        <div className="lg:col-span-1 rounded-2xl border border-zinc-800 bg-zinc-900 p-4 text-center">
          <div className="text-4xl font-black tabular-nums text-white">{total}</div>
          <div className="mt-1 text-xs font-semibold uppercase tracking-widest text-zinc-500">
            Total
          </div>
        </div>

        {/* Per-severity */}
        {SEVERITIES.map((sev) => {
          const cfg   = SEVERITY_CONFIG[sev];
          const count = report.summary[sev];
          return (
            <div
              key={sev}
              className={`rounded-2xl border bg-zinc-900 p-4 text-center transition ${
                count > 0
                  ? `border-zinc-700 ring-1 ${cfg.ring}`
                  : "border-zinc-800 opacity-50"
              }`}
            >
              <div
                className={`text-4xl font-black tabular-nums ${
                  count > 0 ? "text-white" : "text-zinc-600"
                }`}
              >
                {count}
              </div>
              <div className="mt-2">
                <span
                  className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cfg.badge}`}
                >
                  {cfg.label}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* CVSS Dial + Risk Gauge side-by-side */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-[220px_1fr]">
        <CvssDial report={report} />

        {/* Risk Gauge */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900 px-6 py-5 flex flex-col justify-center">
        <div className="flex items-center justify-between mb-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
            Overall Risk Score
          </div>
          <div className={`text-sm font-bold ${risk.color}`}>{risk.label}</div>
        </div>

        {/* Bar */}
        <div className="h-3 rounded-full bg-zinc-800 overflow-hidden">
          <div
            className="h-3 rounded-full transition-all duration-1000 ease-out"
            style={{
              width: `${score}%`,
              background:
                score >= 80
                  ? "linear-gradient(90deg, #dc2626, #ef4444)"
                  : score >= 50
                  ? "linear-gradient(90deg, #f97316, #fb923c)"
                  : score >= 25
                  ? "linear-gradient(90deg, #eab308, #facc15)"
                  : "linear-gradient(90deg, #3b82f6, #60a5fa)",
            }}
          />
        </div>

        {/* Tick marks */}
        <div className="mt-1.5 flex justify-between text-[10px] text-zinc-700">
          <span>0</span>
          <span>Low</span>
          <span>Medium</span>
          <span>High</span>
          <span>Critical</span>
        </div>

        {/* Severity breakdown bars */}
        {total > 0 && (
          <div className="mt-4 flex h-2 rounded-full overflow-hidden gap-px">
            {SEVERITIES.map((sev) => {
              const cfg   = SEVERITY_CONFIG[sev];
              const count = report.summary[sev];
              const pct   = (count / total) * 100;
              if (!count) return null;
              return (
                <div
                  key={sev}
                  className={`${cfg.bar} transition-all duration-700`}
                  style={{ width: `${pct}%` }}
                  title={`${cfg.label}: ${count}`}
                />
              );
            })}
          </div>
        )}
        </div>
      </div>
    </section>
  );
}
