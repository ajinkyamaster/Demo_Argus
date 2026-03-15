import { useState, useEffect, useCallback, useRef } from 'react';
import type { AgentStep, AgentLog, AgentName } from '../types';
import { SCAN_RESULT } from '../data/stubData';
import AgentStepper from './demo/AgentStepper';
import SeverityBar from './demo/SeverityBar';
import type { SeveritySegment } from './demo/SeverityBar';
import StatCards from './demo/StatCards';
import CvssDial from './demo/CvssDial';
import FindingCards from './demo/FindingCards';

/* ── Agent pipeline definition ── */
const AGENT_ORDER: { name: AgentName; color: string; elapsed: string }[] = [
  { name: 'Recon', color: '#0EA5E9', elapsed: '3.2s' },
  { name: 'Web Exploiter', color: 'var(--amber)', elapsed: '8.1s' },
  { name: 'Net Exploiter', color: '#F97316', elapsed: '5.4s' },
  { name: 'CVE Engine', color: 'var(--red)', elapsed: '4.5s' },
  { name: 'Chainer', color: 'var(--purple)', elapsed: '3.8s' },
  { name: 'Report', color: 'var(--green)', elapsed: '2.9s' },
];

/* ── Which agents appear on LEFT vs RIGHT of chat ── */
const LEFT_AGENTS = new Set(['Master', 'Recon', 'CVE Engine', 'Report']);

const AGENT_COLORS: Record<string, string> = {
  Master: 'var(--text-secondary)',
  Recon: '#0EA5E9',
  'Web Exploiter': 'var(--amber)',
  'Net Exploiter': '#F97316',
  'CVE Engine': 'var(--red)',
  Chainer: 'var(--purple)',
  Report: 'var(--green)',
};

const AGENT_CALLSIGNS: Record<string, string> = {
  Master: 'COMMAND',
  Recon: 'RECON-1',
  'Web Exploiter': 'WEB-OPS',
  'Net Exploiter': 'NET-OPS',
  'CVE Engine': 'INTEL',
  Chainer: 'CHAIN-X',
  Report: 'SIGINT',
};

/* ── Map log indices to agents for progressive log reveal ── */
const AGENT_LOG_BATCHES = [
  [0, 1, 2, 3],
  [4, 5, 6, 7, 8],
  [9, 10, 11],
  [12, 13, 14, 15],
  [16, 17, 18],
  [19, 20, 21, 22],
];

export default function DemoPanel({
  scanActive,
  onLaunch,
  onScanComplete,
}: {
  scanActive: boolean;
  onLaunch: () => void;
  onScanComplete?: () => void;
}) {
  const [inputUrl, setInputUrl] = useState('https://demo.acme-corp.com');
  const [running, setRunning] = useState(false);
  const [agents, setAgents] = useState<AgentStep[]>(
    AGENT_ORDER.map((a) => ({ ...a, label: a.name, status: 'waiting' as const }))
  );
  const [visibleLogs, setVisibleLogs] = useState<AgentLog[]>([]);
  const [sevSegments, setSevSegments] = useState<SeveritySegment[]>([]);
  const [sevFlash, setSevFlash] = useState(false);
  const [statsActive, setStatsActive] = useState(false);
  const [dialActive, setDialActive] = useState(false);
  const [findingsVisible, setFindingsVisible] = useState(false);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const chatRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight;
    }
  }, [visibleLogs.length]);

  const resetAll = useCallback(() => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
    setRunning(false);
    setAgents(AGENT_ORDER.map((a) => ({ ...a, label: a.name, status: 'waiting' as const })));
    setVisibleLogs([]);
    setSevSegments([]);
    setSevFlash(false);
    setStatsActive(false);
    setDialActive(false);
    setFindingsVisible(false);
  }, []);

  const runDemo = useCallback(() => {
    resetAll();
    setRunning(true);

    const delay = (ms: number) =>
      new Promise<void>((resolve) => {
        const t = setTimeout(resolve, ms);
        timersRef.current.push(t);
      });

    async function sequence() {
      for (let i = 0; i < AGENT_ORDER.length; i++) {
        setAgents((prev) =>
          prev.map((a, idx) =>
            idx === i ? { ...a, status: 'active' as const } : a
          )
        );
        await delay(1500);

        setAgents((prev) =>
          prev.map((a, idx) =>
            idx === i ? { ...a, status: 'done' as const, elapsed: AGENT_ORDER[i].elapsed } : a
          )
        );

        const logIndices = AGENT_LOG_BATCHES[i] || [];
        const newLogs = logIndices
          .filter((li) => li < SCAN_RESULT.agent_logs.length)
          .map((li) => SCAN_RESULT.agent_logs[li]);
        setVisibleLogs((prev) => [...prev, ...newLogs]);

        if (i === 0) {
          setSevSegments([{ severity: 'LOW', count: 1 }]);
        } else if (i === 1) {
          setSevSegments([
            { severity: 'LOW', count: 1 },
            { severity: 'MEDIUM', count: 2 },
            { severity: 'HIGH', count: 2 },
          ]);
        } else if (i === 3) {
          setSevSegments([
            { severity: 'LOW', count: 1 },
            { severity: 'MEDIUM', count: 2 },
            { severity: 'HIGH', count: 2 },
            { severity: 'CRITICAL', count: 2 },
          ]);
          setSevFlash(true);
        }
      }

      await delay(400);
      setStatsActive(true);
      setDialActive(true);

      // Smooth auto-scroll to scan results
      await delay(300);
      const resultsEl = document.getElementById('demo-results');
      if (resultsEl) {
        resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }

      await delay(500);
      setFindingsVisible(true);
      await delay(800);
      onScanComplete?.();
    }

    sequence();
  }, [inputUrl, resetAll, onScanComplete]);

  useEffect(() => {
    if (scanActive && !running) runDemo();
  }, [scanActive, running, runDemo]);

  useEffect(() => {
    return () => timersRef.current.forEach(clearTimeout);
  }, []);

  const criticalVulns = SCAN_RESULT.vulnerabilities.filter(v => v.severity === 'CRITICAL');
  const highVulns = SCAN_RESULT.vulnerabilities.filter(v => v.severity === 'HIGH');
  const medVulns = SCAN_RESULT.vulnerabilities.filter(v => v.severity === 'MEDIUM');
  const lowVulns = SCAN_RESULT.vulnerabilities.filter(v => v.severity === 'LOW');

  return (
    <section id="demo" style={{ padding: '140px 40px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div className="reveal" data-delay="0">
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: 'var(--green)',
          marginBottom: 8,
        }}>
          // LIVE DEMO
        </p>
        <h2 style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: 'clamp(32px, 5vw, 48px)',
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0,
        }}>
          Watch Argus hunt.
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: 16, marginTop: 8 }}>
          Enter any URL. Watch six AI agents deploy in sequence.
        </p>
      </div>

      {/* Scan input bar */}
      <div className="reveal" data-delay="100" style={{ maxWidth: 800, margin: '40px auto 0' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }} className="scan-input-row">
          <input
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            placeholder="https://target.example.com"
            style={{
              flex: 1, height: 52, background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 10, padding: '0 20px', fontFamily: "'JetBrains Mono', monospace",
              fontSize: 15, color: 'var(--text-primary)', outline: 'none',
              transition: 'border-color 200ms ease, box-shadow 200ms ease',
            }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-glow)';
              e.currentTarget.style.boxShadow = '0 0 0 3px var(--green-dim)';
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = 'var(--border)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          />
          <button
            onClick={() => { if (!running) { onLaunch(); runDemo(); } }}
            disabled={running}
            style={{
              height: 52, padding: '0 28px',
              background: running ? 'var(--bg-panel)' : 'transparent',
              color: running ? 'var(--text-muted)' : 'var(--green)',
              border: running ? '1px solid var(--border)' : '1px solid var(--border-glow)',
              borderRadius: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600,
              cursor: running ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap',
              transition: 'background 200ms ease, box-shadow 200ms ease, transform 200ms ease',
            }}
            className="launch-scan-btn"
            onMouseEnter={(e) => { if (!running) { e.currentTarget.style.background = 'var(--green-dim)'; e.currentTarget.style.boxShadow = '0 0 30px rgba(0,229,160,0.2), 0 0 60px rgba(0,229,160,0.08)'; e.currentTarget.style.transform = 'translateY(-1px)'; } }}
            onMouseLeave={(e) => { e.currentTarget.style.background = running ? 'var(--bg-panel)' : 'transparent'; e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.transform = 'none'; }}
          >
            {running ? 'Scanning...' : 'Launch Scan'}
          </button>
        </div>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
          color: 'var(--text-muted)', marginTop: 10, textAlign: 'center',
        }}>
          ↳ Demo mode — using stub data
        </p>
      </div>

      {/* Severity bar */}
      {running && (
        <div style={{ maxWidth: 800, margin: '28px auto 0' }}>
          <SeverityBar segments={sevSegments} flash={sevFlash} />
        </div>
      )}

      {/* ── Side-by-side: AgentStepper + Chat (separate cards) ── */}
      {running && (
        <div style={{ display: 'flex', gap: 16, marginTop: 40, alignItems: 'stretch', height: 640 }} className="demo-side-layout">

          {/* ── Left card: Agent timeline stepper ── */}
          <div style={{
            flex: '0 0 260px',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '11px 16px',
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg-panel)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <div style={{
                width: 7, height: 7, borderRadius: '50%',
                background: 'var(--green)',
                boxShadow: '0 0 6px rgba(0,229,160,0.5)',
                animation: 'pulse-dot 2s ease-in-out infinite',
              }} />
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                color: 'var(--green)', textTransform: 'uppercase',
                letterSpacing: '0.1em', fontWeight: 700,
              }}>
                AGENT PIPELINE
              </span>
            </div>
            <div style={{ padding: '16px 16px' }}>
              <AgentStepper agents={agents} />
            </div>
          </div>

          {/* ── Right card: Scrollable chat ── */}
          <div style={{
            flex: 1, minWidth: 0,
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
          }}>
            <div style={{
              padding: '11px 20px',
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg-panel)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: 'var(--green)',
                  boxShadow: '0 0 6px rgba(0,229,160,0.5)',
                  animation: 'pulse-dot 2s ease-in-out infinite',
                }} />
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                  color: 'var(--green)', textTransform: 'uppercase',
                  letterSpacing: '0.1em', fontWeight: 700,
                }}>
                  AGENT COMMS
                </span>
              </div>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                color: 'var(--text-muted)', letterSpacing: '0.06em',
              }}>
                {visibleLogs.length} messages
              </span>
            </div>

            {/* Scrollable chat body — fixed height, scrolls internally */}
            <div
              ref={chatRef}
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '16px 20px',
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
              }}
            >
              {visibleLogs.length === 0 && (
                <div style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center',
                  justifyContent: 'center', height: '100%', gap: 12,
                }}>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.12em',
                  }}>
                    Waiting for agents...
                  </span>
                  <div style={{
                    width: 40, height: 2, background: 'var(--green)',
                    opacity: 0.4, animation: 'chatPulse 1.5s ease-in-out infinite',
                  }} />
                </div>
              )}

              {visibleLogs.map((log, i) => {
                const isLeft = LEFT_AGENTS.has(log.agent);
                const isMaster = log.agent === 'Master';
                const color = AGENT_COLORS[log.agent] || 'var(--text-muted)';
                const callsign = AGENT_CALLSIGNS[log.agent] || log.agent;

                return (
                  <div
                    key={i}
                    style={{
                      display: 'flex', flexDirection: 'column',
                      alignItems: isLeft ? 'flex-start' : 'flex-end',
                      opacity: 0,
                      animation: `chatBubbleIn 0.35s ease-out ${(i % 8) * 50}ms forwards`,
                    }}
                  >
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4,
                      flexDirection: isLeft ? 'row' : 'row-reverse',
                    }}>
                      <span style={{
                        display: 'inline-block', width: 6, height: 6, borderRadius: '50%',
                        background: color, boxShadow: `0 0 5px ${color}`,
                      }} />
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace", fontSize: 10, fontWeight: 700,
                        color, textTransform: 'uppercase', letterSpacing: '0.06em',
                      }}>
                        {callsign}
                      </span>
                      {isMaster && (
                        <span style={{
                          fontFamily: "'JetBrains Mono', monospace", fontSize: 8,
                          color: 'var(--green)', background: 'var(--green-dim)',
                          border: '1px solid rgba(0,229,160,0.2)',
                          padding: '1px 5px', borderRadius: 2,
                          textTransform: 'uppercase', letterSpacing: '0.06em',
                        }}>
                          PRIORITY
                        </span>
                      )}
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                        color: 'var(--text-muted)', opacity: 0.6,
                      }}>
                        {log.timestamp}
                      </span>
                    </div>

                    <div style={{
                      maxWidth: '82%',
                      padding: '9px 13px',
                      borderRadius: isLeft ? '3px 12px 12px 12px' : '12px 3px 12px 12px',
                      background: isMaster
                        ? 'rgba(0,229,160,0.06)'
                        : isLeft ? 'var(--bg-panel)' : 'rgba(255,255,255,0.03)',
                      border: isMaster
                        ? '1px solid rgba(0,229,160,0.12)'
                        : '1px solid var(--border)',
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      color: isMaster ? 'var(--text-primary)' : 'var(--text-secondary)',
                      lineHeight: 1.6,
                    }}>
                      {log.message}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Post-scan: Instrument panel ── */}
      {statsActive && (
        <div id="demo-results" style={{
          marginTop: 48,
          borderRadius: 16,
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          overflow: 'hidden',
        }}>
          {/* Panel header */}
          <div style={{
            padding: '12px 24px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-panel)',
            display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: 'var(--green)',
              boxShadow: '0 0 8px rgba(0,229,160,0.5)',
              animation: 'pulse-dot 2s ease-in-out infinite',
            }} />
            <span style={{
              fontFamily: "'Space Grotesk', sans-serif", fontSize: 14, fontWeight: 600,
              color: 'var(--text-primary)', letterSpacing: '0.02em',
            }}>
              Scan Results
            </span>
            <div style={{ flex: 1 }} />
            <span style={{
              fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
              color: 'var(--green)', letterSpacing: '0.06em',
              background: 'var(--green-dim)', padding: '3px 10px', borderRadius: 100,
              border: '1px solid rgba(0,229,160,0.15)',
            }}>
              COMPLETE
            </span>
          </div>

          {/* Dial hero area — centered with subtle radial glow */}
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            padding: '40px 24px 28px',
            background: 'radial-gradient(ellipse 400px 200px at 50% 40%, rgba(0,229,160,0.03) 0%, transparent 70%)',
          }}>
            {dialActive && (
              <>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                  color: 'var(--text-muted)', textTransform: 'uppercase',
                  letterSpacing: '0.15em', marginBottom: 16,
                }}>
                  MAX CVSS SCORE
                </div>
                <CvssDial score={SCAN_RESULT.summary.max_cvss} active={dialActive} />
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                  color: 'var(--text-muted)', marginTop: 8,
                }}>
                  {SCAN_RESULT.target}
                </div>
              </>
            )}
          </div>

          {/* Divider */}
          <div style={{ height: 1, background: 'var(--border)', margin: '0 24px' }} />

          {/* Stats table below */}
          <div style={{ padding: '20px 24px 24px' }}>
            <StatCards summary={SCAN_RESULT.summary} active={statsActive} />
          </div>
        </div>
      )}

      {/* ── Vulnerability Breakdown — 2×2 grid with badge headers + scrollable cards ── */}
      {findingsVisible && (
        <div style={{ marginTop: 48 }}>
          <h3 style={{
            fontFamily: "'Space Grotesk', sans-serif", fontSize: 24, fontWeight: 700,
            color: 'var(--text-primary)', marginBottom: 12, textAlign: 'center',
          }}>
            Vulnerability Breakdown
          </h3>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
            color: 'var(--text-muted)', textAlign: 'center', marginBottom: 32,
          }}>
            {SCAN_RESULT.summary.total_findings} findings across {SCAN_RESULT.vulnerabilities.length} targets
          </p>

          {/* Badge row */}
          <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginBottom: 28, flexWrap: 'wrap' }}>
            {([
              { label: 'CRITICAL', count: criticalVulns.length, color: 'var(--red)', glow: 'rgba(255,59,59,0.3)' },
              { label: 'HIGH',     count: highVulns.length,     color: 'var(--amber)', glow: 'rgba(245,158,11,0.3)' },
              { label: 'MEDIUM',   count: medVulns.length,      color: 'var(--blue)', glow: 'rgba(59,130,246,0.3)' },
              { label: 'LOW',      count: lowVulns.length,      color: 'var(--green)', glow: 'rgba(0,229,160,0.3)' },
            ] as const).map((b) => (
              <div key={b.label} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                background: 'var(--bg-surface)', border: '1px solid var(--border)',
                borderRadius: 100, padding: '7px 18px',
              }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%', background: b.color,
                  display: 'inline-block', boxShadow: `0 0 8px ${b.glow}`,
                }} />
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700,
                  color: b.color, letterSpacing: '0.06em',
                }}>
                  {b.count}
                </span>
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                  color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em',
                }}>
                  {b.label}
                </span>
              </div>
            ))}
          </div>

          {/* 2×2 grid */}
          <div
            style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 24 }}
            className="vuln-2x2"
          >
            {([
              { label: 'CRITICAL', findings: criticalVulns, color: 'var(--red)', glow: 'rgba(255,59,59,0.3)' },
              { label: 'HIGH',     findings: highVulns,     color: 'var(--amber)', glow: 'rgba(245,158,11,0.3)' },
              { label: 'MEDIUM',   findings: medVulns,      color: 'var(--blue)', glow: 'rgba(59,130,246,0.3)' },
              { label: 'LOW',      findings: lowVulns,      color: 'var(--green)', glow: 'rgba(0,229,160,0.3)' },
            ] as const).map((section) => (
              <div key={section.label} style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: 12,
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
              }}>
                {/* Section header */}
                <div style={{
                  padding: '12px 20px',
                  borderBottom: '1px solid var(--border)',
                  background: 'var(--bg-panel)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%', background: section.color,
                      display: 'inline-block', boxShadow: `0 0 6px ${section.glow}`,
                    }} />
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700,
                      color: section.color, textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>
                      {section.label}
                    </span>
                  </div>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                    color: 'var(--text-muted)',
                  }}>
                    {section.findings.length} {section.findings.length === 1 ? 'finding' : 'findings'}
                  </span>
                </div>

                {/* Scrollable findings area */}
                <div style={{
                  padding: 20,
                  maxHeight: 420,
                  overflowY: 'auto',
                  flex: 1,
                }}>
                  {section.findings.length > 0 ? (
                    <FindingCards findings={section.findings} />
                  ) : (
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      height: 80, fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 11, color: 'var(--text-muted)',
                    }}>
                      No {section.label.toLowerCase()} findings
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <style>{`
        @keyframes chatBubbleIn {
          from { opacity: 0; transform: translateY(8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes chatPulse {
          0%, 100% { opacity: 0.2; transform: scaleX(0.8); }
          50% { opacity: 0.6; transform: scaleX(1.2); }
        }
        @media (max-width: 900px) {
          .demo-side-layout {
            flex-direction: column !important;
            height: auto !important;
          }
          .demo-side-layout > div:first-child {
            flex: unset !important;
            width: 100% !important;
            border-right: none !important;
            border-bottom: 1px solid var(--border) !important;
          }
          .demo-side-layout > div:last-child {
            height: 500px !important;
          }
        }
        @media (max-width: 768px) {
          .scan-input-row {
            flex-direction: column !important;
          }
          .scan-input-row input, .scan-input-row button {
            width: 100% !important;
          }
          .vuln-2x2 {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
