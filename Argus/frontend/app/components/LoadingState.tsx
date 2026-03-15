"use client";

import { useEffect, useState, useRef } from "react";

const AGENT_STEPS = [
  { agent: "ReconAgent",  action: "Enumerating endpoints…" },
  { agent: "SQLiAgent",   action: "Probing SQL injection vectors…" },
  { agent: "XSSAgent",    action: "Testing cross-site scripting payloads…" },
  { agent: "AuthAgent",   action: "Analysing authentication flows…" },
  { agent: "AuthAgent",   action: "Checking IDOR on user resources…" },
  { agent: "SynthAgent",  action: "Synthesising final report…" },
];

const AGENT_COLORS: Record<string, string> = {
  ReconAgent: "text-cyan-400",
  SQLiAgent:  "text-red-400",
  XSSAgent:   "text-orange-400",
  AuthAgent:  "text-yellow-400",
  SynthAgent: "text-green-400",
};

interface TerminalLine {
  agent: string;
  text: string;
  type: "info" | "vuln" | "done";
}

const TERMINAL_SCRIPT: TerminalLine[] = [
  { agent: "system",     text: "Initialising Argus agent crew...",                type: "info" },
  { agent: "ReconAgent", text: "Starting endpoint enumeration on target",         type: "info" },
  { agent: "ReconAgent", text: "GET /api/login .............. 200 OK",            type: "info" },
  { agent: "ReconAgent", text: "GET /api/users/:id .......... 200 OK",            type: "info" },
  { agent: "ReconAgent", text: "GET /api/search ............. 200 OK",            type: "info" },
  { agent: "ReconAgent", text: "GET /api/characters ......... 200 OK",            type: "info" },
  { agent: "ReconAgent", text: "Discovered 5 endpoints. Handing off to scanners.", type: "done" },
  { agent: "SQLiAgent",  text: "Probing /api/login for SQL injection...",          type: "info" },
  { agent: "SQLiAgent",  text: "Payload: ' OR '1'='1' --",                        type: "vuln" },
  { agent: "SQLiAgent",  text: "VULNERABLE — HTTP 200 with admin token returned", type: "vuln" },
  { agent: "AuthAgent",  text: "Testing JWT secret strength...",                   type: "info" },
  { agent: "AuthAgent",  text: "VULNERABLE — hardcoded secret 'supersecret'",     type: "vuln" },
  { agent: "XSSAgent",   text: "Testing /api/search?q= for reflected XSS...",     type: "info" },
  { agent: "XSSAgent",   text: "VULNERABLE — payload reflected unescaped",        type: "vuln" },
  { agent: "AuthAgent",  text: "Checking IDOR on /api/users/2...",                type: "info" },
  { agent: "AuthAgent",  text: "VULNERABLE — user 1 accessed user 2 PII",        type: "vuln" },
  { agent: "SynthAgent", text: "All agents complete. Generating report...",        type: "done" },
];

export function LoadingState() {
  const [step, setStep]       = useState(0);
  const [done, setDone]       = useState<number[]>([]);
  const [dots, setDots]       = useState("");
  const [lines, setLines]     = useState<TerminalLine[]>([]);
  const [typedTarget, setTypedTarget] = useState("");
  const termRef = useRef<HTMLDivElement>(null);

  const targetUrl = "http://localhost:5000";

  // Typewriter for target URL
  useEffect(() => {
    let i = 0;
    const iv = setInterval(() => {
      i++;
      setTypedTarget(targetUrl.slice(0, i));
      if (i >= targetUrl.length) clearInterval(iv);
    }, 60);
    return () => clearInterval(iv);
  }, []);

  // Dots animation
  useEffect(() => {
    const iv = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "" : d + "."));
    }, 400);
    return () => clearInterval(iv);
  }, []);

  // Agent step ticker
  useEffect(() => {
    const iv = setInterval(() => {
      setStep((s) => {
        setDone((prev) => [...prev, s]);
        return Math.min(s + 1, AGENT_STEPS.length - 1);
      });
    }, 1600);
    return () => clearInterval(iv);
  }, []);

  // Terminal line feed
  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    TERMINAL_SCRIPT.forEach((line, i) => {
      timers.push(
        setTimeout(() => {
          setLines((prev) => [...prev, line]);
        }, 800 + i * 350),
      );
    });
    return () => timers.forEach(clearTimeout);
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="space-y-4">
      {/* Terminal panel */}
      <section className="rounded-2xl border border-zinc-800 bg-[#0D0F14] overflow-hidden">
        {/* macOS title bar */}
        <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/80 px-4 py-2">
          <span className="h-2.5 w-2.5 rounded-full bg-red-500 opacity-70" />
          <span className="h-2.5 w-2.5 rounded-full bg-yellow-500 opacity-70" />
          <span className="h-2.5 w-2.5 rounded-full bg-green-500 opacity-70" />
          <span className="ml-2 text-xs text-zinc-600 terminal">argus — live scan</span>
          <span className="ml-auto relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-red-600" />
          </span>
        </div>

        {/* Terminal body */}
        <div
          ref={termRef}
          className="p-4 h-52 overflow-y-auto text-xs terminal leading-relaxed"
        >
          {/* Typewriter target line */}
          <div className="mb-2">
            <span className="text-green-500">argus</span>
            <span className="text-zinc-600">@</span>
            <span className="text-blue-500">localhost</span>
            <span className="text-zinc-600">:~$ </span>
            <span className="text-zinc-300">scan {typedTarget}</span>
            {typedTarget.length < targetUrl.length && (
              <span className="animate-blink text-zinc-400">█</span>
            )}
          </div>

          {/* Log lines */}
          {lines.map((line, i) => (
            <div key={i} className="animate-slide-in" style={{ animationDelay: `${i * 20}ms` }}>
              <span className="text-zinc-700">[</span>
              <span className={AGENT_COLORS[line.agent] ?? "text-zinc-500"}>
                {line.agent.padEnd(11)}
              </span>
              <span className="text-zinc-700">] </span>
              <span
                className={
                  line.type === "vuln"
                    ? "text-red-400 font-bold"
                    : line.type === "done"
                    ? "text-green-400"
                    : "text-zinc-400"
                }
              >
                {line.text}
              </span>
            </div>
          ))}

          {/* Blinking cursor at bottom */}
          <div className="mt-1">
            <span className="text-green-500">argus</span>
            <span className="text-zinc-600">:~$ </span>
            <span className="animate-blink text-zinc-500">█</span>
          </div>
        </div>

        {/* Scan line overlay */}
        <div className="h-0.5 bg-zinc-900 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600 to-transparent animate-[scan-line_2s_linear_infinite]" />
        </div>
      </section>

      {/* Agent stepper card */}
      <section className="rounded-2xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        <div className="flex items-center gap-3 border-b border-zinc-800 px-5 py-3">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-red-600" />
          </span>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-zinc-400">
            Agent Pipeline
          </h2>
        </div>

        <div className="p-4 space-y-2">
          {AGENT_STEPS.map((s, i) => {
            const isDone   = done.includes(i);
            const isActive = step === i && !isDone;

            return (
              <div
                key={i}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-xs transition-all duration-500 ${
                  isActive
                    ? "bg-red-950/30 border border-red-800/50"
                    : isDone
                    ? "bg-zinc-800/30 border border-transparent"
                    : "border border-transparent opacity-30"
                }`}
              >
                <div className="flex-shrink-0 w-4">
                  {isDone ? (
                    <svg className="h-4 w-4 text-green-500" viewBox="0 0 16 16" fill="none">
                      <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.5" />
                      <path d="M5 8l2.5 2.5L11 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  ) : isActive ? (
                    <span className="block h-4 w-4 rounded-full border-2 border-red-500 border-t-transparent animate-spin" />
                  ) : (
                    <span className="block h-4 w-4 rounded-full border border-zinc-700" />
                  )}
                </div>

                <span className={`font-bold terminal ${
                  isActive ? "text-red-400" : isDone ? "text-green-400" : "text-zinc-600"
                }`}>
                  {s.agent}
                </span>
                <span className={`${isActive ? "text-zinc-300" : isDone ? "text-zinc-500" : "text-zinc-700"}`}>
                  {isActive ? `${s.action}${dots}` : s.action}
                </span>
              </div>
            );
          })}
        </div>

        {/* Progress bar */}
        <div className="px-5 pb-4">
          <div className="h-1 rounded-full bg-zinc-800">
            <div
              className="h-1 rounded-full bg-red-600 transition-all duration-700"
              style={{ width: `${Math.round((done.length / AGENT_STEPS.length) * 100)}%` }}
            />
          </div>
          <div className="mt-1.5 flex justify-between text-[10px] text-zinc-600">
            <span>{done.length} / {AGENT_STEPS.length} agents</span>
            <span>{Math.round((done.length / AGENT_STEPS.length) * 100)}%</span>
          </div>
        </div>
      </section>
    </div>
  );
}
