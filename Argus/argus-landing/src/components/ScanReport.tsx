import { useState } from 'react';
import type { ScanResult, Severity } from '../types';

const C = {
  bg:        '#0A0A0A',
  surface:   '#111111',
  border:    '#1A1A1A',
  borderHi:  '#252525',
  green:     '#00E5A0',
  greenDim:  'rgba(0,229,160,0.07)',
  text:      '#E4E4E7',
  textMid:   '#8B8B8B',
  textDim:   '#4A4A4A',
  textGhost: '#2E2E2E',
};

const SEV_LABEL: Record<Severity, string> = {
  CRITICAL: 'CRIT', HIGH: 'HIGH', MEDIUM: 'MED', LOW: 'LOW',
};

type Tab = 'overview' | 'findings' | 'chains' | 'blockchain';
const MONO = "'JetBrains Mono', 'Fira Code', monospace";

export default function ScanReport({ result }: { result: ScanResult }) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview',   label: 'overview'    },
    { key: 'findings',   label: `findings(${result.vulnerabilities.length})` },
    { key: 'chains',     label: 'kill-chains' },
    { key: 'blockchain', label: 'proof'       },
  ];

  return (
    <section style={{ padding: '100px 40px 80px', maxWidth: 1400, margin: '0 auto', minHeight: '100vh', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 12, overflow: 'hidden', flex: 1 }}>

        {/* ── Title bar ── */}
        <div style={{
          display: 'flex', alignItems: 'center', padding: '10px 16px',
          background: C.surface, borderBottom: `1px solid ${C.border}`, gap: 10,
        }}>
          <div style={{ display: 'flex', gap: 6, marginRight: 8 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#555', opacity: 0.5 }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#555', opacity: 0.5 }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#555', opacity: 0.5 }} />
          </div>
          <span style={{ fontFamily: MONO, fontSize: 12, color: C.textDim }}>argus@pentest:</span>
          <span style={{ fontFamily: MONO, fontSize: 12, color: C.green }}>~/reports/{result.scan_id.slice(0, 8)}</span>
          <div style={{ flex: 1 }} />
          <span style={{ fontFamily: MONO, fontSize: 10, color: C.textDim }}>{result.timestamp.split('T')[0]}</span>
        </div>

        {/* ── Command prompt ── */}
        <div style={{ padding: '14px 20px', borderBottom: `1px solid ${C.border}`, background: C.bg }}>
          <div style={{ fontFamily: MONO, fontSize: 13, color: C.textMid, lineHeight: 1.8 }}>
            <span style={{ color: C.green }}>$</span>{' '}
            argus scan --target <span style={{ color: C.green }}>{result.target}</span>
          </div>
          <div style={{ fontFamily: MONO, fontSize: 12, color: C.textDim, marginTop: 4 }}>
            <span style={{ color: C.green }}>✓</span>{' '}
            Scan complete · {result.summary.total_findings} findings · {result.summary.scan_duration}
          </div>
        </div>

        {/* ── Tab bar ── */}
        <div style={{ display: 'flex', borderBottom: `1px solid ${C.border}`, background: C.surface }}>
          {tabs.map((tab) => {
            const active = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                style={{
                  fontFamily: MONO, fontSize: 12,
                  color: active ? C.green : C.textDim,
                  background: active ? C.bg : 'transparent',
                  border: 'none',
                  borderBottom: active ? `2px solid ${C.green}` : '2px solid transparent',
                  borderRight: `1px solid ${C.border}`,
                  padding: '10px 18px', cursor: 'pointer',
                  transition: 'color 120ms ease',
                }}
                onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = C.textMid; }}
                onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = C.textDim; }}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* ── Tab content ── */}
        <div style={{ padding: '32px 36px', minHeight: 500 }}>

          {/* OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Scan Summary
              </div>

              {/* Stat grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1, background: C.border, borderRadius: 4, overflow: 'hidden' }} className="report-stat-grid">
                {[
                  { label: 'TOTAL',    value: result.summary.total_findings     },
                  { label: 'CRITICAL', value: result.summary.critical_count      },
                  { label: 'MAX CVSS', value: result.summary.max_cvss.toFixed(1) },
                  { label: 'ELAPSED',  value: result.summary.scan_duration       },
                ].map((item, i) => (
                  <div key={i} style={{ background: C.surface, padding: '16px', textAlign: 'center' }}>
                    <div style={{ fontFamily: MONO, fontSize: 8, color: C.textDim, textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 10 }}>
                      {item.label}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: 26, fontWeight: 700, color: C.text, lineHeight: 1 }}>
                      {item.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* Severity bar — green only with opacity */}
              <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: '16px' }}>
                <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, marginBottom: 12, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  Severity Distribution
                </div>
                <div style={{ display: 'flex', height: 4, gap: 1, borderRadius: 2, overflow: 'hidden', marginBottom: 12 }}>
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((sev) => {
                    const count = result.vulnerabilities.filter((v) => v.severity === sev).length;
                    if (count === 0) return null;
                    const pct = (count / result.vulnerabilities.length) * 100;
                    const opacity = sev === 'CRITICAL' ? 1 : sev === 'HIGH' ? 0.7 : sev === 'MEDIUM' ? 0.45 : 0.25;
                    return <div key={sev} style={{ width: `${pct}%`, background: C.green, opacity }} />;
                  })}
                </div>
                <div style={{ display: 'flex', gap: 20 }}>
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((sev) => {
                    const count = result.vulnerabilities.filter((v) => v.severity === sev).length;
                    return (
                      <span key={sev} style={{ fontFamily: MONO, fontSize: 11, color: C.textMid, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ color: C.textGhost }}>■</span>
                        {count} {SEV_LABEL[sev]}
                      </span>
                    );
                  })}
                </div>
              </div>

              {/* Threat assessment */}
              <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.green}`, borderRadius: 4, padding: '16px' }}>
                <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  Threat Assessment
                </div>
                <div style={{ fontFamily: MONO, fontSize: 12, color: C.textMid, lineHeight: 1.8 }}>
                  Target contains <span style={{ color: C.green }}>2 critical vulnerabilities</span> enabling full RCE and database compromise.
                  Kill chain confirmed: SSTI → complete DB exfiltration with zero authentication.
                  Immediate remediation required. <span style={{ color: C.green }}>Auto-generated patches available.</span>
                </div>
              </div>

              <div style={{ fontFamily: MONO, fontSize: 12, color: C.textDim }}>
                <span style={{ color: C.green }}>$</span>{' '}
                <span style={{ color: C.green, animation: 'blink-cursor 1s step-end infinite', display: 'inline-block' }}>█</span>
              </div>
            </div>
          )}

          {/* FINDINGS */}
          {activeTab === 'findings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>
                Vulnerability Findings
              </div>

              {result.vulnerabilities.map((vuln, vi) => {
                const isExpanded = expandedVuln === vuln.id;
                const hasPatch = vuln.patch_code !== null;

                return (
                  <div key={vuln.id} style={{
                    background: C.surface, border: `1px solid ${C.border}`,
                    borderRadius: 4, overflow: 'hidden', cursor: 'pointer',
                    transition: 'border-color 150ms ease',
                  }}
                    onClick={() => setExpandedVuln(isExpanded ? null : vuln.id)}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.borderHi; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; }}
                  >
                    <div style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontFamily: MONO, fontSize: 10, color: C.textGhost }}>[{String(vi).padStart(2, '0')}]</span>
                      <span style={{
                        fontFamily: MONO, fontSize: 10, fontWeight: 700,
                        color: C.green, background: C.greenDim,
                        padding: '2px 7px', borderRadius: 2, letterSpacing: '0.05em',
                      }}>
                        {SEV_LABEL[vuln.severity]}
                      </span>
                      <span style={{ fontFamily: MONO, fontSize: 13, color: C.text, flex: 1 }}>{vuln.title}</span>
                      <span style={{ fontFamily: MONO, fontSize: 13, color: C.textMid, fontWeight: 700, flexShrink: 0 }}>
                        {vuln.cvss_score.toFixed(1)}
                      </span>
                      {hasPatch && (
                        <span style={{
                          fontFamily: MONO, fontSize: 9, color: C.green,
                          background: C.greenDim, border: `1px solid ${C.green}25`,
                          padding: '2px 6px', borderRadius: 2,
                        }}>
                          PATCH
                        </span>
                      )}
                      <span style={{
                        fontFamily: MONO, fontSize: 10, color: C.textDim,
                        transform: isExpanded ? 'rotate(90deg)' : 'none',
                        transition: 'transform 150ms ease', display: 'inline-block',
                      }}>▶</span>
                    </div>

                    {isExpanded && (
                      <div style={{ padding: '14px', borderTop: `1px solid ${C.border}`, background: C.bg }}>
                        <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, marginBottom: 10, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                          {vuln.severity} — {vuln.affected_component}
                          {vuln.cve_ids.length > 0 && (
                            <span style={{ color: C.textMid, marginLeft: 12 }}>{vuln.cve_ids.join(', ')}</span>
                          )}
                        </div>
                        <div style={{ fontFamily: MONO, fontSize: 12, color: C.textMid, lineHeight: 1.8, marginBottom: 14 }}>
                          {vuln.description}
                        </div>

                        {vuln.patch_code && (
                          <div>
                            <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, marginBottom: 10, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                              Patch Diff — {vuln.patch_code.file_path}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }} className="patch-grid">
                              <div>
                                <div style={{ fontFamily: MONO, fontSize: 10, color: C.textDim, marginBottom: 6 }}>--- vulnerable</div>
                                <pre style={{
                                  background: 'rgba(255,255,255,0.02)', border: `1px solid ${C.border}`,
                                  borderRadius: 3, padding: '10px 12px', fontFamily: MONO,
                                  fontSize: 11, color: C.textMid, lineHeight: 1.6,
                                  overflowX: 'auto', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                }}>
                                  {vuln.patch_code.vulnerable_snippet}
                                </pre>
                              </div>
                              <div>
                                <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, marginBottom: 6 }}>+++ patched</div>
                                <pre style={{
                                  background: C.greenDim, border: `1px solid ${C.green}15`,
                                  borderRadius: 3, padding: '10px 12px', fontFamily: MONO,
                                  fontSize: 11, color: C.text, lineHeight: 1.6,
                                  overflowX: 'auto', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                }}>
                                  {vuln.patch_code.fixed_snippet}
                                </pre>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}

              <div style={{ fontFamily: MONO, fontSize: 12, color: C.textDim, marginTop: 6 }}>
                <span style={{ color: C.green }}>$</span>{' '}
                <span style={{ color: C.green, animation: 'blink-cursor 1s step-end infinite', display: 'inline-block' }}>█</span>
              </div>
            </div>
          )}

          {/* ATTACK CHAINS */}
          {activeTab === 'chains' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>
                Attack Chain Traces
              </div>

              {[
                {
                  id: 'CHAIN-01', title: 'Full Database Compromise',
                  meta: '5 stages · no-auth · cvss:10.0',
                  steps: ['SSTI /search', 'RCE Jinja2', 'Read Flask ENV', 'Extract DB_URL', 'Full DB Dump'],
                },
                {
                  id: 'CHAIN-02', title: 'Credential Theft + Persistence',
                  meta: '3 stages · no-auth · cvss:9.1',
                  steps: ['SQLi /auth', 'Dump Creds', 'Admin Takeover'],
                },
              ].map((chain) => (
                <div key={chain.id} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 10, borderBottom: `1px solid ${C.border}` }}>
                    <span style={{
                      fontFamily: MONO, fontSize: 10, fontWeight: 700,
                      color: C.bg, background: C.green, padding: '3px 7px', borderRadius: 2,
                    }}>
                      {chain.id}
                    </span>
                    <span style={{ fontFamily: MONO, fontSize: 13, fontWeight: 600, color: C.text }}>{chain.title}</span>
                    <div style={{ flex: 1 }} />
                    <span style={{ fontFamily: MONO, fontSize: 10, color: C.textDim }}>{chain.meta}</span>
                  </div>
                  <div style={{ padding: '14px 16px' }}>
                    <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      Trace Path
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 0 }}>
                      {chain.steps.map((step, i, arr) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
                          <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 3, padding: '5px 10px' }}>
                            <span style={{ fontFamily: MONO, fontSize: 11, color: C.text }}>{step}</span>
                          </div>
                          {i < arr.length - 1 && (
                            <span style={{ fontFamily: MONO, fontSize: 11, color: C.green, margin: '0 3px', opacity: 0.5 }}>──▸</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}

              <div style={{ fontFamily: MONO, fontSize: 12, color: C.textDim, marginTop: 4 }}>
                <span style={{ color: C.green }}>$</span>{' '}
                <span style={{ color: C.green, animation: 'blink-cursor 1s step-end infinite', display: 'inline-block' }}>█</span>
              </div>
            </div>
          )}

          {/* BLOCKCHAIN PROOF */}
          {activeTab === 'blockchain' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontFamily: MONO, fontSize: 10, color: C.green, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>
                On-Chain Verification
              </div>

              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                background: C.greenDim, border: `1px solid ${C.green}20`,
                borderRadius: 4, padding: '10px 16px', alignSelf: 'flex-start',
              }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
                <span style={{ fontFamily: MONO, fontSize: 12, color: C.green }}>ANCHORED ON-CHAIN</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: C.border, borderRadius: 4, overflow: 'hidden' }} className="blockchain-detail-grid">
                {[
                  { label: 'tx_hash',     value: result.blockchain.tx_hash },
                  { label: 'block',        value: `#${result.blockchain.block_number.toLocaleString()}` },
                  { label: 'report_hash',  value: result.blockchain.report_hash },
                  { label: 'timestamp',    value: result.blockchain.timestamp },
                ].map((item, i) => (
                  <div key={i} style={{ background: C.surface, padding: '14px' }}>
                    <div style={{ fontFamily: MONO, fontSize: 9, color: C.green, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      {item.label}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: 12, color: C.text, wordBreak: 'break-all', lineHeight: 1.5 }}>
                      {item.value}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ fontFamily: MONO, fontSize: 12, color: C.textDim, marginTop: 4 }}>
                <span style={{ color: C.green }}>$</span>{' '}
                <span style={{ color: C.green, animation: 'blink-cursor 1s step-end infinite', display: 'inline-block' }}>█</span>
              </div>
            </div>
          )}
        </div>

        {/* ── Status bar ── */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '8px 16px', borderTop: `1px solid ${C.border}`, background: C.surface,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontFamily: MONO, fontSize: 11 }}>
            <span style={{ color: C.green }}>● READY</span>
            <span style={{ color: C.textGhost }}>│</span>
            <span style={{ color: C.textDim }}>argus v2.4.1</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontFamily: MONO, fontSize: 11 }}>
            <span style={{ color: C.textDim }}>{result.scan_id.slice(0, 8).toUpperCase()}</span>
            <span style={{ color: C.textGhost }}>│</span>
            <span style={{ color: C.textDim }}>{result.vulnerabilities.length} findings</span>
            <span style={{ color: C.textGhost }}>│</span>
            <span style={{ color: C.textDim }}>UTF-8</span>
          </div>
        </div>
      </div>

      {/* Download button */}
      <div style={{ textAlign: 'center', marginTop: 40 }}>
        <button
          onClick={() => window.print()}
          className="dl-report-btn"
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 10,
            padding: '13px 32px',
            background: 'transparent',
            border: `1px solid ${C.green}40`,
            borderRadius: 8,
            fontFamily: MONO,
            fontSize: 13, fontWeight: 600,
            color: C.green,
            cursor: 'pointer',
            transition: 'background 200ms ease, box-shadow 200ms ease, transform 200ms ease',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          Download Detailed Report
        </button>
        <p style={{
          fontFamily: MONO,
          fontSize: 11, color: C.textDim, marginTop: 10,
        }}>
          Opens browser print dialog — save as PDF
        </p>
      </div>

      <style>{`
        .dl-report-btn:hover {
          background: ${C.greenDim} !important;
          box-shadow: 0 0 30px rgba(0,229,160,0.2), 0 0 60px rgba(0,229,160,0.08) !important;
          transform: translateY(-1px) !important;
        }
        @media (max-width: 768px) {
          .report-stat-grid       { grid-template-columns: repeat(2, 1fr) !important; }
          .patch-grid             { grid-template-columns: 1fr !important; }
          .blockchain-detail-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </section>
  );
}
