/* ── Agent SVG Icons (simple path-based, 24px) ── */

function ReconIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0EA5E9" strokeWidth="1.5" strokeLinecap="round">
      {/* Radar pulse */}
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2a10 10 0 0 1 10 10" />
      <path d="M12 6a6 6 0 0 1 6 6" />
    </svg>
  );
}

function WebExploiterIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" strokeWidth="1.5" strokeLinecap="round">
      {/* Spider web */}
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2v20M2 12h20" />
      <path d="M4.93 4.93l14.14 14.14M19.07 4.93L4.93 19.07" />
    </svg>
  );
}

function NetExploiterIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#F97316" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {/* Network/server */}
      <rect x="2" y="3" width="20" height="6" rx="1" />
      <rect x="2" y="15" width="20" height="6" rx="1" />
      <path d="M12 9v6" />
      <circle cx="6" cy="6" r="1" fill="#F97316" />
      <circle cx="6" cy="18" r="1" fill="#F97316" />
    </svg>
  );
}

function CveEngineIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--red)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {/* Shield with X */}
      <path d="M12 2l8 4v6c0 5.5-3.8 8.2-8 10-4.2-1.8-8-4.5-8-10V6l8-4z" />
      <path d="M9 9l6 6M15 9l-6 6" />
    </svg>
  );
}

function ChainerIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" strokeWidth="1.5" strokeLinecap="round">
      {/* Chain links */}
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  );
}

function ReportIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {/* Document with checkmark */}
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <path d="M9 15l2 2 4-4" />
    </svg>
  );
}

const AGENTS = [
  {
    num: '01',
    name: 'Recon',
    color: '#0EA5E9',
    Icon: ReconIcon,
    description: 'Maps the entire attack surface using BS4, gau, and requests. Port scanning, subdomain enumeration, tech fingerprinting.',
    finds: ['Open ports & services', 'Subdomains', 'Tech stack fingerprint'],
  },
  {
    num: '02',
    name: 'Web Exploiter',
    color: 'var(--amber)',
    Icon: WebExploiterIcon,
    description: 'Fuzzes every endpoint for injection flaws — SQLi, XSS, LFI, SSTI. Tests authentication and input validation.',
    finds: ['SQLi, XSS, SSTI, LFI', 'Auth bypasses', 'Input validation flaws'],
  },
  {
    num: '03',
    name: 'Net Exploiter',
    color: '#F97316',
    Icon: NetExploiterIcon,
    description: 'Probes network-layer vulnerabilities using nmap and banner grabbing. Identifies exposed services and misconfigurations.',
    finds: ['Nmap banner grabs', 'Exposed services', 'Network misconfigs'],
  },
  {
    num: '04',
    name: 'CVE Engine',
    color: 'var(--red)',
    Icon: CveEngineIcon,
    description: 'Cross-references findings against the NVD API. Maps vulnerabilities to known CVEs with CVSS scoring. Master-gated, sequential after Recon.',
    finds: ['CVE mappings', 'CVSS scores', 'Public exploit PoCs'],
  },
  {
    num: '05',
    name: 'Chainer',
    color: 'var(--purple)',
    Icon: ChainerIcon,
    description: 'Connects individual findings into multi-step attack chains using chain_engine.py. Pure Python, no LLM dependency.',
    finds: ['Attack chains', 'Lateral movement paths', 'Privilege escalation'],
  },
  {
    num: '06',
    name: 'Report',
    color: 'var(--green)',
    Icon: ReportIcon,
    description: 'Generates exec summary, patch code, and risk matrix using Groq LLM + Pydantic schema. Anchors report hash to blockchain.',
    finds: ['Executive summary', 'Code patches', 'Blockchain tx_hash'],
  },
];

export default function HowItWorks() {
  return (
    <section
      id="how-it-works"
      style={{
        padding: '140px 40px',
        maxWidth: 1400,
        margin: '0 auto',
        position: 'relative',
      }}
    >
      {/* Background radial glow */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(ellipse at center, rgba(59,130,246,0.04) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      {/* Header */}
      <div className="reveal" data-delay="0" style={{ position: 'relative', textAlign: 'center', marginBottom: 80 }}>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: 'var(--green)',
          marginBottom: 8,
        }}>
          // METHODOLOGY
        </p>
        <h2 style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: 'clamp(32px, 5vw, 48px)',
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0,
        }}>
          Six agents. One mission.
        </h2>
        <p style={{
          fontFamily: "'DM Sans', sans-serif",
          fontSize: 16,
          color: 'var(--text-secondary)',
          marginTop: 12,
          maxWidth: 500,
          marginLeft: 'auto',
          marginRight: 'auto',
        }}>
          Each agent is a specialist. Together, they think like a senior red team.
        </p>
      </div>

      {/* Agent cards — 3-col grid */}
      <div style={{ position: 'relative' }}>
        <div
          className="timeline-grid"
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: 24,
            position: 'relative',
            zIndex: 1,
          }}
        >
          {AGENTS.map((agent, i) => (
            <div
              key={agent.num}
              className="reveal"
              data-delay={String(i * 100)}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: 12,
                padding: 28,
                position: 'relative',
                overflow: 'hidden',
                cursor: 'default',
                transition: 'transform 200ms ease, border-color 200ms ease, background 200ms ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-4px)';
                e.currentTarget.style.borderColor = 'var(--border-glow)';
                e.currentTarget.style.background = 'var(--bg-panel)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.background = 'var(--bg-surface)';
              }}
            >
              {/* Watermark number */}
              <span style={{
                position: 'absolute',
                top: -8,
                right: 8,
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 56,
                fontWeight: 700,
                color: agent.color,
                opacity: 0.08,
                lineHeight: 1,
                pointerEvents: 'none',
                userSelect: 'none',
              }}>
                {agent.num}
              </span>

              {/* Icon */}
              <div style={{ marginBottom: 14 }}>
                <agent.Icon />
              </div>

              {/* Agent name */}
              <div style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 16,
                fontWeight: 600,
                color: 'var(--text-primary)',
                marginBottom: 10,
              }}>
                {agent.name}
              </div>

              {/* Description */}
              <div style={{
                fontFamily: "'DM Sans', sans-serif",
                fontSize: 13,
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
                marginBottom: 14,
              }}>
                {agent.description}
              </div>

              {/* Finds list */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {agent.finds.map((item, fi) => (
                  <span
                    key={fi}
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 11,
                      color: 'var(--green)',
                    }}
                  >
                    → {item}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Responsive */}
      <style>{`
        @media (max-width: 900px) {
          .timeline-grid {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
        @media (max-width: 500px) {
          .timeline-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
