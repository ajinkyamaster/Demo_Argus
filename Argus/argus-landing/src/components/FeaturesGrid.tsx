/* ═══════════════════════════════════
   Mini feature previews for each card
   ═══════════════════════════════════ */

function MiniTerminal() {
  const lines = [
    { text: '[14:22:38] Recon → 3 subdomains found', color: 'var(--green)' },
    { text: '[14:22:49] Web Exploiter → SSTI CONFIRMED', color: 'var(--amber)' },
    { text: '[14:22:56] Net Exploiter → PG 13.2 exposed', color: '#F97316' },
    { text: '[14:22:58] CVE Engine → CVSS 9.8 CRITICAL', color: 'var(--red)' },
  ];
  return (
    <div style={{
      background: 'var(--bg-void)',
      borderRadius: 8,
      padding: '10px 12px',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 10,
      lineHeight: 1.8,
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Scanline effect */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,229,160,0.02) 2px, rgba(0,229,160,0.02) 3px)',
        pointerEvents: 'none',
      }} />
      {lines.map((l, i) => (
        <div key={i} style={{ color: l.color }}>{l.text}</div>
      ))}
    </div>
  );
}

function MiniCvssDial() {
  const size = 80;
  const cx = size / 2, cy = size / 2, r = 30, sw = 6;
  const startDeg = 160, totalDeg = 220;
  const frac = 0.98; // 9.8 / 10
  function polar(deg: number) {
    const rad = (deg * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }
  function arc(f: number) {
    const end = startDeg + totalDeg * f;
    const s = polar(startDeg), e = polar(end);
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${totalDeg * f > 180 ? 1 : 0} 1 ${e.x} ${e.y}`;
  }
  return (
    <div style={{ display: 'flex', justifyContent: 'center' }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <path d={arc(1)} stroke="var(--bg-panel)" strokeWidth={sw} fill="none" strokeLinecap="round" />
        <path d={arc(frac)} stroke="#CC0000" strokeWidth={sw} fill="none" strokeLinecap="round" />
        <text x={cx} y={cy - 2} textAnchor="middle" dominantBaseline="central"
          style={{ fontFamily: "'Space Grotesk'", fontSize: 16, fontWeight: 700, fill: '#CC0000' }}>9.8</text>
        <text x={cx} y={cy + 12} textAnchor="middle" dominantBaseline="central"
          style={{ fontFamily: "'JetBrains Mono'", fontSize: 7, fill: '#CC0000' }}>CRITICAL</text>
      </svg>
    </div>
  );
}

function MiniThreatGraph() {
  const nodes = [
    { x: 60, y: 40, color: 'var(--text-muted)', r: 5, label: 'target' },
    { x: 25, y: 20, color: 'var(--red)', r: 4 },
    { x: 95, y: 18, color: 'var(--red)', r: 4 },
    { x: 20, y: 60, color: 'var(--amber)', r: 3.5 },
    { x: 100, y: 58, color: 'var(--amber)', r: 3.5 },
    { x: 60, y: 72, color: 'var(--blue)', r: 3 },
  ];
  const edges = [[0,1],[0,2],[0,3],[0,4],[0,5],[1,2],[3,5]];
  return (
    <svg width="120" height="80" viewBox="0 0 120 80" style={{ display: 'block', margin: '0 auto' }}>
      {edges.map(([a,b], i) => (
        <line key={i} x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y}
          stroke="var(--border)" strokeWidth="0.8" />
      ))}
      {nodes.map((n, i) => (
        <circle key={i} cx={n.x} cy={n.y} r={n.r} fill={n.color} opacity={0.9}>
          <animate attributeName="r" values={`${n.r};${n.r+1};${n.r}`} dur="3s" repeatCount="indefinite" />
        </circle>
      ))}
    </svg>
  );
}

function MiniChat() {
  const msgs = [
    { agent: 'Recon', color: '#0EA5E9', text: 'Port 5432 open — PostgreSQL' },
    { agent: 'Web Exploiter', color: 'var(--amber)', text: 'SSTI confirmed at /search' },
    { agent: 'CVE Engine', color: 'var(--red)', text: 'CVE-2024-3094 mapped' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {msgs.map((m, i) => (
        <div key={i} style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderLeft: `2px solid ${m.color}`,
          borderRadius: 6,
          padding: '6px 10px',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 9,
          color: 'var(--text-secondary)',
        }}>
          <span style={{ color: m.color, marginRight: 6 }}>{m.agent}</span>
          {m.text}
        </div>
      ))}
    </div>
  );
}

function MiniCardStack() {
  const cards = [
    { sev: 'CRITICAL', color: 'var(--red)', rot: -2 },
    { sev: 'HIGH', color: 'var(--amber)', rot: 0 },
    { sev: 'MEDIUM', color: 'var(--blue)', rot: 1.5 },
  ];
  return (
    <div style={{ position: 'relative', height: 70, display: 'flex', justifyContent: 'center' }}>
      {cards.map((c, i) => (
        <div key={i} style={{
          position: 'absolute',
          top: i * 4,
          transform: `rotate(${c.rot}deg)`,
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderLeft: `3px solid ${c.color}`,
          borderRadius: 6,
          padding: '8px 14px',
          width: 120,
          zIndex: 3 - i,
        }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 8,
            color: c.color,
            background: i === 0 ? 'var(--red-dim)' : 'transparent',
            padding: '1px 5px',
            borderRadius: 3,
          }}>
            {c.sev}
          </span>
        </div>
      ))}
    </div>
  );
}

function MiniBlockchain() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        background: 'var(--green-dim)',
        border: '1px solid var(--border-glow)',
        borderRadius: 100,
        padding: '4px 12px',
        alignSelf: 'flex-start',
      }}>
        <span style={{ color: 'var(--green)', fontSize: 12 }}>✓</span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--green)' }}>
          Report anchored on-chain
        </span>
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: 'var(--text-muted)' }}>
        tx: 0x8f3a...e2b9
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: 'var(--text-muted)' }}>
        block: #18,847,293
      </div>
    </div>
  );
}


/* ═══════════════════════════════════
   Bento grid layout
   ═══════════════════════════════════ */

const FEATURES = [
  { title: 'Live Terminal Scan', size: 'large' as const, Preview: MiniTerminal },
  { title: 'CVSS Severity Dial', size: 'small' as const, Preview: MiniCvssDial },
  { title: 'D3 Threat Graph', size: 'small' as const, Preview: MiniThreatGraph },
  { title: 'Agent Chat', size: 'small' as const, Preview: MiniChat },
  { title: 'Finding Cards', size: 'small' as const, Preview: MiniCardStack },
  { title: 'Blockchain Anchor', size: 'large' as const, Preview: MiniBlockchain },
];

function BentoCard({ title, delay, children }: { title: string; delay: number; children: React.ReactNode }) {
  return (
    <div
      className="reveal"
      data-delay={String(delay)}
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 16,
        padding: 32,
        overflow: 'hidden',
        transition: 'border-color 200ms ease, box-shadow 200ms ease',
        cursor: 'default',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'var(--border-glow)';
        e.currentTarget.style.boxShadow = '0 20px 60px rgba(0,0,0,0.4)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--border)';
        e.currentTarget.style.boxShadow = 'none';
      }}
    >
      <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 16 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

export default function FeaturesGrid() {
  return (
    <section id="features" style={{ padding: '140px 40px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div className="reveal" data-delay="0" style={{ textAlign: 'center', marginBottom: 80 }}>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: 'var(--green)',
          marginBottom: 8,
        }}>
          // CAPABILITIES
        </p>
        <h2 style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: 'clamp(32px, 5vw, 48px)',
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0,
        }}>
          Built for the stage. Built for production.
        </h2>
        <p style={{
          fontFamily: "'DM Sans', sans-serif",
          fontSize: 16,
          color: 'var(--text-secondary)',
          marginTop: 12,
        }}>
          Every feature designed to make findings impossible to ignore.
        </p>
      </div>

      {/* Bento Grid — stacked rows */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* Row 1: 60% + 40% */}
        <div className="bento-row" style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: 24 }}>
          {[0, 1].map((idx) => {
            const Preview = FEATURES[idx].Preview;
            return (
              <BentoCard key={idx} title={FEATURES[idx].title} delay={idx * 80}>
                <Preview />
              </BentoCard>
            );
          })}
        </div>

        {/* Row 2: 3 equal cards */}
        <div className="bento-row bento-row-3" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 24 }}>
          {[2, 3, 4].map((idx, i) => {
            const Preview = FEATURES[idx].Preview;
            return (
              <BentoCard key={idx} title={FEATURES[idx].title} delay={i * 80}>
                <Preview />
              </BentoCard>
            );
          })}
        </div>

        {/* Row 3: Full-width Blockchain Anchor */}
        <div className="bento-row">
          {(() => {
            const Preview = FEATURES[5].Preview;
            return (
              <BentoCard key={5} title={FEATURES[5].title} delay={0}>
                <Preview />
              </BentoCard>
            );
          })()}
        </div>

      </div>

      <style>{`
        @media (max-width: 768px) {
          .bento-row {
            grid-template-columns: 1fr !important;
          }
          .bento-row-3 {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
