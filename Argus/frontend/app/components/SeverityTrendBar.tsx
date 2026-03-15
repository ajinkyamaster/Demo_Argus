"use client";

import { ScanReport, Severity, SEVERITY_CONFIG } from "./types";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityTrendBar({ report }: { report: ScanReport | null }) {
  if (!report || report.summary.total_vulnerabilities === 0) return null;

  const total = report.summary.total_vulnerabilities;
  const hasCritical = report.summary.critical > 0;

  return (
    <div
      className={`fixed top-0 left-0 right-0 z-[9999] h-1.5 flex pointer-events-none ${
        hasCritical ? "critical-flash" : ""
      }`}
    >
      {ORDER.map((sev) => {
        const count = report.summary[sev];
        if (!count) return null;
        const cfg = SEVERITY_CONFIG[sev];
        const pct = (count / total) * 100;
        return (
          <div
            key={sev}
            className={`${cfg.bar} transition-all duration-700 ease-out`}
            style={{ width: `${pct}%` }}
          />
        );
      })}
    </div>
  );
}
