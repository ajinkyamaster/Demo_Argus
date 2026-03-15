"use client";

import { useState } from "react";
import {
  Shield, Target, Zap, Settings2, ChevronDown, ChevronUp, Play,
} from "lucide-react";
import {
  ScanMode, Module, ScanRequest, MODULE_META,
} from "./types";

interface Props {
  onScan: (req: ScanRequest) => void;
  loading: boolean;
  useStub: boolean;
  onUseStubChange: (v: boolean) => void;
}

const ALL_MODULES: Module[] = ["sqli", "xss", "auth", "idor", "csrf", "path_traversal"];

export function ScanForm({ onScan, loading, useStub, onUseStubChange }: Props) {
  const [targetUrl, setTargetUrl] = useState("http://localhost:5000");
  const [scanMode, setScanMode]   = useState<ScanMode>("full");
  const [modules, setModules]     = useState<Set<Module>>(new Set(ALL_MODULES));
  const [depth, setDepth]         = useState(3);
  const [timeout, setTimeout_]    = useState(30);
  const [verbose, setVerbose]     = useState(false);
  const [advOpen, setAdvOpen]     = useState(false);

  function toggleModule(m: Module) {
    setModules((prev) => {
      const next = new Set(prev);
      next.has(m) ? next.delete(m) : next.add(m);
      return next;
    });
  }

  function submit() {
    onScan({
      target_url: targetUrl,
      scan_mode: scanMode,
      modules: Array.from(modules),
      options: { depth, timeout, verbose },
    });
  }

  const modeOptions: { value: ScanMode; label: string; desc: string }[] = [
    { value: "quick",   label: "Quick",   desc: "Surface-level probes only" },
    { value: "full",    label: "Full",    desc: "All modules, deep analysis" },
    { value: "focused", label: "Focused", desc: "Selected modules only" },
  ];

  return (
    <section className="rounded-2xl glass overflow-hidden">
      {/* Panel header */}
      <div className="flex items-center gap-3 border-b border-white/5 px-6 py-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-red-600/20">
          <Shield className="h-3.5 w-3.5 text-red-500" />
        </div>
        <h2 className="text-sm font-bold uppercase tracking-widest text-zinc-200">
          Configure Scan
        </h2>
      </div>

      <div className="p-6 space-y-5">
        {/* Target URL */}
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            <Target className="h-3.5 w-3.5" />
            Target URL
          </label>
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:5000"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm font-mono
                       text-zinc-100 placeholder-zinc-600 transition
                       focus:border-red-600 focus:outline-none focus:ring-2 focus:ring-red-600/30"
          />
        </div>

        {/* Scan Mode */}
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            <Zap className="h-3.5 w-3.5" />
            Scan Mode
          </label>
          <div className="grid grid-cols-3 gap-2">
            {modeOptions.map(({ value, label, desc }) => (
              <button
                key={value}
                type="button"
                onClick={() => setScanMode(value)}
                className={`rounded-lg border px-4 py-3 text-left transition ${
                  scanMode === value
                    ? "border-red-600 bg-red-600/10 text-white ring-1 ring-red-600/40"
                    : "border-zinc-700 bg-zinc-800 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200"
                }`}
              >
                <div className="text-sm font-semibold">{label}</div>
                <div className="text-[11px] text-zinc-500 mt-0.5">{desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Module Checkboxes */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
              Attack Modules
            </label>
            <div className="flex gap-2 text-xs">
              <button
                type="button"
                onClick={() => setModules(new Set(ALL_MODULES))}
                className="text-zinc-500 hover:text-zinc-300 transition"
              >
                All
              </button>
              <span className="text-zinc-700">·</span>
              <button
                type="button"
                onClick={() => setModules(new Set())}
                className="text-zinc-500 hover:text-zinc-300 transition"
              >
                None
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {ALL_MODULES.map((m) => {
              const active = modules.has(m);
              return (
                <button
                  key={m}
                  type="button"
                  onClick={() => toggleModule(m)}
                  className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm transition ${
                    active
                      ? "border-red-700 bg-red-950/40 text-red-300"
                      : "border-zinc-800 bg-zinc-800/50 text-zinc-500 hover:border-zinc-700 hover:text-zinc-300"
                  }`}
                >
                  <span
                    className={`h-2 w-2 flex-shrink-0 rounded-full transition ${
                      active ? "bg-red-500" : "bg-zinc-700"
                    }`}
                  />
                  <span className="text-xs font-medium">{MODULE_META[m].label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Advanced Options (collapsible) */}
        <div className="rounded-lg border border-zinc-800">
          <button
            type="button"
            onClick={() => setAdvOpen((v) => !v)}
            className="flex w-full items-center justify-between px-4 py-3 text-xs font-semibold
                       uppercase tracking-wider text-zinc-500 hover:text-zinc-300 transition"
          >
            <span className="flex items-center gap-2">
              <Settings2 className="h-3.5 w-3.5" />
              Advanced Options
            </span>
            {advOpen ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>

          {advOpen && (
            <div className="border-t border-zinc-800 px-4 py-4 space-y-4 animate-fade-in-up">
              {/* Depth */}
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-xs font-semibold text-zinc-300">Depth</div>
                  <div className="text-[11px] text-zinc-600">Crawl depth (1–10)</div>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setDepth((v) => Math.max(1, v - 1))}
                    className="h-7 w-7 rounded-full border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition flex items-center justify-center text-lg leading-none"
                  >
                    −
                  </button>
                  <span className="w-6 text-center text-sm font-mono font-bold text-zinc-100">
                    {depth}
                  </span>
                  <button
                    type="button"
                    onClick={() => setDepth((v) => Math.min(10, v + 1))}
                    className="h-7 w-7 rounded-full border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition flex items-center justify-center text-lg leading-none"
                  >
                    +
                  </button>
                </div>
              </div>

              {/* Timeout */}
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-xs font-semibold text-zinc-300">Timeout</div>
                  <div className="text-[11px] text-zinc-600">Seconds per action (5–120)</div>
                </div>
                <div className="flex items-center gap-3">
                  <input
                    type="range"
                    min={5}
                    max={120}
                    step={5}
                    value={timeout}
                    onChange={(e) => setTimeout_(Number(e.target.value))}
                    className="w-28 accent-red-600"
                  />
                  <span className="w-10 text-right text-sm font-mono text-zinc-300">
                    {timeout}s
                  </span>
                </div>
              </div>

              {/* Verbose */}
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-zinc-300">Verbose Logs</div>
                  <div className="text-[11px] text-zinc-600">Populate full agent trace</div>
                </div>
                <button
                  type="button"
                  onClick={() => setVerbose((v) => !v)}
                  className={`relative h-5 w-9 rounded-full transition-colors ${
                    verbose ? "bg-red-600" : "bg-zinc-700"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${
                      verbose ? "translate-x-4" : "translate-x-0.5"
                    }`}
                  />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer: stub checkbox + launch button */}
        <div className="flex items-center justify-between gap-4 pt-2">
          <label className="flex cursor-pointer items-center gap-2 text-xs text-zinc-500 hover:text-zinc-300 transition select-none">
            <input
              type="checkbox"
              checked={useStub}
              onChange={(e) => onUseStubChange(e.target.checked)}
              className="accent-red-500 h-3.5 w-3.5"
            />
            Use stub data
          </label>

          <button
            type="button"
            onClick={submit}
            disabled={loading || modules.size === 0}
            className="flex items-center gap-2 rounded-lg bg-red-600 px-6 py-2.5 text-sm font-bold
                       uppercase tracking-wider hover:bg-red-500 disabled:opacity-40
                       transition-all active:scale-95 glow-red"
          >
            <Play className="h-4 w-4 fill-current" />
            {loading ? "Scanning…" : "Launch Scan"}
          </button>
        </div>
      </div>
    </section>
  );
}
