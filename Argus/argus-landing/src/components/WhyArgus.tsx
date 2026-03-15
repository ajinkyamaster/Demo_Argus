const TRAITS = [
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M2 12C2 12 5.5 5 12 5C18.5 5 22 12 22 12C22 12 18.5 19 12 19C5.5 19 2 12 2 12Z" />
      </svg>
    ),
    title: 'The 100 Eyes',
    subtitle: 'Scans Every Corner',
    desc: 'Like the hundred eyes of Argus Panoptes, our agents inspect every endpoint, header, parameter, and hidden surface — nothing escapes observation.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
        <circle cx="12" cy="12" r="4" />
      </svg>
    ),
    title: 'Never Sleeps',
    subtitle: 'Always-On Security',
    desc: 'Argus Panoptes never truly slept — only a few eyes closed at a time. Our autonomous agents provide continuous, tireless penetration testing around the clock.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5" />
        <path d="M2 12l10 5 10-5" />
      </svg>
    ),
    title: 'Shining Clarity',
    subtitle: 'Illuminates the Hidden',
    desc: 'The Greek word "argos" means bright or shining. Argus shines a light on hidden vulnerabilities, transforming dark unknowns into clear, actionable intelligence.',
  },
];

export default function WhyArgus() {
  return (
    <section id="why-argus" style={{ padding: '120px 40px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div className="reveal" data-delay="0" style={{ textAlign: 'center', marginBottom: 64 }}>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: 'var(--green)', marginBottom: 8,
        }}>
          // THE NAME
        </p>
        <h2 style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: 'clamp(28px, 5vw, 44px)', fontWeight: 700,
          color: 'var(--text-primary)', margin: '0 0 16px',
        }}>
          Why <span style={{ color: 'var(--green)' }}>Argus</span>?
        </h2>
        <p style={{
          fontFamily: "'DM Sans', sans-serif",
          fontSize: 16, color: 'var(--text-secondary)',
          maxWidth: 700, margin: '0 auto', lineHeight: 1.7,
        }}>
          Named after <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Argus Panoptes</span> — the all-seeing giant of Greek mythology with a hundred eyes, the ultimate guardian who could never be caught unaware.
        </p>
      </div>

      {/* 3-column trait cards */}
      <div
        style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 24 }}
        className="argus-trait-grid"
      >
        {TRAITS.map((trait, i) => (
          <div
            key={trait.title}
            className="reveal argus-trait-card"
            data-delay={String(i * 100)}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 16,
              padding: '36px 28px',
              display: 'flex', flexDirection: 'column', gap: 16,
              transition: 'border-color 250ms ease, box-shadow 250ms ease, transform 250ms ease',
            }}
          >
            {/* Icon */}
            <div style={{
              width: 52, height: 52,
              borderRadius: 12,
              background: 'var(--green-dim)',
              border: '1px solid rgba(0,229,160,0.12)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {trait.icon}
            </div>

            {/* Title + subtitle */}
            <div>
              <div style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 18, fontWeight: 700, color: 'var(--text-primary)',
                marginBottom: 4,
              }}>
                {trait.title}
              </div>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10, color: 'var(--green)',
                textTransform: 'uppercase', letterSpacing: '0.1em',
              }}>
                {trait.subtitle}
              </div>
            </div>

            {/* Description */}
            <p style={{
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 14, color: 'var(--text-secondary)',
              lineHeight: 1.7, margin: 0,
            }}>
              {trait.desc}
            </p>
          </div>
        ))}
      </div>

      {/* Bottom quote */}
      <div className="reveal" data-delay="300" style={{
        textAlign: 'center', marginTop: 48, padding: '28px 32px',
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 12, maxWidth: 700, margin: '48px auto 0',
        borderLeft: '3px solid var(--green)',
      }}>
        <p style={{
          fontFamily: "'DM Sans', sans-serif",
          fontSize: 15, color: 'var(--text-secondary)',
          lineHeight: 1.8, margin: 0, fontStyle: 'italic',
        }}>
          "Six autonomous agents. Every endpoint examined. Every vulnerability illuminated.
          Like its mythological namesake — <span style={{ color: 'var(--green)', fontWeight: 500, fontStyle: 'normal' }}>Argus never blinks.</span>"
        </p>
      </div>

      <style>{`
        .argus-trait-card:hover {
          border-color: var(--border-glow) !important;
          box-shadow: 0 8px 40px rgba(0,0,0,0.3), 0 0 30px rgba(0,229,160,0.04) !important;
          transform: translateY(-3px) !important;
        }
        @media (max-width: 768px) {
          .argus-trait-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
