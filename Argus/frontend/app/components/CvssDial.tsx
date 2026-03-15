"use client";

import { useEffect, useRef, useState } from "react";
import { ScanReport } from "./types";

function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
}

function cvssColor(score: number): string {
  if (score >= 9.0) return "#dc2626"; // red-600
  if (score >= 7.0) return "#f97316"; // orange-500
  if (score >= 4.0) return "#eab308"; // yellow-500
  if (score > 0)    return "#3b82f6"; // blue-500
  return "#52525b";                    // zinc-600
}

function severityLabel(score: number): { text: string; cls: string } {
  if (score >= 9.0) return { text: "CRITICAL", cls: "text-red-500" };
  if (score >= 7.0) return { text: "HIGH",     cls: "text-orange-400" };
  if (score >= 4.0) return { text: "MEDIUM",   cls: "text-yellow-400" };
  if (score > 0)    return { text: "LOW",      cls: "text-blue-400" };
  return                   { text: "NONE",     cls: "text-green-400" };
}

export function CvssDial({ report }: { report: ScanReport }) {
  const maxCvss = report.vulnerabilities.reduce(
    (max, v) => (v.cvss_score != null && v.cvss_score > max ? v.cvss_score : max),
    0,
  );
  const criticalCount = report.vulnerabilities.filter((v) => v.severity === "critical").length;

  // SVG arc params: 220-degree arc
  const size     = 180;
  const stroke   = 10;
  const radius   = (size - stroke) / 2;
  const cx       = size / 2;
  const cy       = size / 2;
  const startAng = 160;                 // degrees (bottom-left)
  const endAng   = 380;                 // 160 + 220
  const arcLen   = 2 * Math.PI * radius * (220 / 360);

  function polarToXY(angleDeg: number) {
    const rad = (angleDeg * Math.PI) / 180;
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  }

  const p1 = polarToXY(startAng);
  const p2 = polarToXY(endAng);

  const arcPath = [
    `M ${p1.x} ${p1.y}`,
    `A ${radius} ${radius} 0 1 1 ${p2.x} ${p2.y}`,
  ].join(" ");

  // Animated score with RAF
  const [displayed, setDisplayed] = useState(0);
  const rafRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);
  const duration = 1200;

  useEffect(() => {
    startRef.current = null;

    function tick(ts: number) {
      if (!startRef.current) startRef.current = ts;
      const elapsed = ts - startRef.current;
      const t = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
      setDisplayed(lerp(0, maxCvss, eased));
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [maxCvss]);

  const fillFrac = displayed / 10;
  const dashOffset = arcLen * (1 - fillFrac);
  const color = cvssColor(displayed);
  const sev = severityLabel(maxCvss);
  const isCritical = maxCvss >= 9.0;

  // Find the CVE that scored highest
  const topVuln = report.vulnerabilities.reduce<{ title: string; cvss_score: number } | null>(
    (best, v) => (!best || v.cvss_score > best.cvss_score ? v : best),
    null,
  );

  return (
    <div
      className={`rounded-2xl border bg-zinc-900 p-6 text-center transition ${
        isCritical
          ? "border-red-800/60 ring-1 ring-red-600/30 dial-critical-glow"
          : "border-zinc-800"
      }`}
    >
      <div className="text-xs font-semibold uppercase tracking-wider text-zinc-500 mb-4">
        Max CVSS Score
      </div>

      {/* SVG gauge */}
      <div className="relative mx-auto" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="block">
          {/* Background arc */}
          <path
            d={arcPath}
            fill="none"
            stroke="rgb(39 39 42)"
            strokeWidth={stroke}
            strokeLinecap="round"
          />
          {/* Filled arc */}
          <path
            d={arcPath}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={arcLen}
            strokeDashoffset={dashOffset}
            style={{ transition: "stroke 0.3s" }}
          />
        </svg>

        {/* Center score */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-4xl font-black font-mono tabular-nums leading-none"
            style={{ color }}
          >
            {displayed.toFixed(1)}
          </span>
          <span className={`text-xs font-bold uppercase tracking-widest mt-1 ${sev.cls}`}>
            {sev.text}
          </span>
        </div>
      </div>

      {/* Sub-labels */}
      <div className="mt-3 flex items-center justify-center gap-1 text-xs text-zinc-600">
        <span>0.0</span>
        <div className="flex-1 h-px bg-zinc-800 mx-2" />
        <span>10.0</span>
      </div>

      {criticalCount > 1 && (
        <div className="mt-2 text-xs text-red-500 font-semibold">
          ({criticalCount} criticals found)
        </div>
      )}

      {topVuln && (
        <div className="mt-3 text-xs text-zinc-500 truncate max-w-[220px] mx-auto">
          {topVuln.title}
        </div>
      )}
    </div>
  );
}
