"use client";

import { useState } from "react";
import { Terminal, ChevronDown, ChevronUp } from "lucide-react";
import { AgentLog } from "./types";

const AGENT_COLORS: Record<string, string> = {
  ReconAgent:  "text-cyan-400",
  SQLiAgent:   "text-red-400",
  XSSAgent:    "text-orange-400",
  AuthAgent:   "text-yellow-400",
  SynthAgent:  "text-green-400",
};

function agentColor(agent: string) {
  return AGENT_COLORS[agent] ?? "text-purple-400";
}

// Highlight CVE IDs, severity keywords, and VULNERABLE/PARTIAL markers
function highlightText(text: string) {
  const parts = text.split(
    /(CVE-\d{4}-\d{4,}|VULNERABLE|PARTIAL|CRITICAL|HIGH|MEDIUM|LOW)/g,
  );
  return parts.map((part, i) => {
    if (/^CVE-\d{4}-\d{4,}$/.test(part))
      return <span key={i} className="rounded bg-red-900/50 px-1 text-red-400 font-bold">{part}</span>;
    if (part === "VULNERABLE")
      return <span key={i} className="rounded bg-red-900/40 px-1 text-red-400 font-bold">{part}</span>;
    if (part === "PARTIAL")
      return <span key={i} className="rounded bg-yellow-900/40 px-1 text-yellow-400 font-bold">{part}</span>;
    if (part === "CRITICAL")
      return <span key={i} className="text-red-500 font-bold">{part}</span>;
    if (part === "HIGH")
      return <span key={i} className="text-orange-400 font-bold">{part}</span>;
    if (part === "MEDIUM")
      return <span key={i} className="text-yellow-400 font-bold">{part}</span>;
    if (part === "LOW")
      return <span key={i} className="text-blue-400 font-bold">{part}</span>;
    return part;
  });
}

export function AgentLogs({ logs }: { logs: AgentLog[] }) {
  const [expanded, setExpanded] = useState(true);

  return (
    <section className="space-y-3 animate-fade-in-up">
      {/* Section header */}
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between group"
      >
        <h2 className="flex items-center gap-2 text-base font-bold text-zinc-100">
          <Terminal className="h-4 w-4 text-red-500" />
          Agent Logs
          <span className="ml-1 rounded-full bg-zinc-800 px-2 py-0.5 text-xs font-mono text-zinc-400">
            {logs.length}
          </span>
        </h2>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 transition" />
        ) : (
          <ChevronDown className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 transition" />
        )}
      </button>

      {expanded && (
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950 overflow-hidden animate-fade-in-up">
          {/* Terminal title bar */}
          <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900 px-4 py-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500 opacity-70" />
            <span className="h-2.5 w-2.5 rounded-full bg-yellow-500 opacity-70" />
            <span className="h-2.5 w-2.5 rounded-full bg-green-500 opacity-70" />
            <span className="ml-2 text-xs text-zinc-600 terminal">argus — agent trace</span>
          </div>

          {/* Log entries */}
          <div className="divide-y divide-zinc-900">
            {logs.map((log, i) => (
              <div
                key={i}
                className="px-5 py-3 hover:bg-zinc-900/50 transition animate-slide-in"
                style={{ animationDelay: `${i * 40}ms` }}
              >
                <div className="flex items-center gap-3 text-xs mb-1">
                  {/* Agent name */}
                  <span
                    className={`terminal font-bold w-28 flex-shrink-0 ${agentColor(log.agent)}`}
                  >
                    {log.agent}
                  </span>
                  {/* Timestamp */}
                  <span className="text-zinc-600 terminal flex-shrink-0">
                    {new Date(log.timestamp).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                    })}
                  </span>
                  {/* Separator */}
                  <span className="text-zinc-800">│</span>
                  {/* Action */}
                  <span className="text-zinc-300 font-medium truncate">{log.action}</span>
                </div>
                {/* Result indented */}
                <div className="ml-[calc(7rem+1.75rem+0.75rem+1.25rem)] text-xs text-zinc-500 leading-relaxed">
                  <span className="text-zinc-700 mr-2">→</span>
                  {highlightText(log.result)}
                </div>
              </div>
            ))}
          </div>

          {/* Terminal footer */}
          <div className="border-t border-zinc-900 px-5 py-2">
            <span className="text-xs terminal text-zinc-700">
              <span className="text-green-600">argus</span>
              <span className="text-zinc-600">@</span>
              <span className="text-blue-600">localhost</span>
              <span className="text-zinc-600">:~$ </span>
              <span className="animate-blink text-zinc-500">█</span>
            </span>
          </div>
        </div>
      )}
    </section>
  );
}
