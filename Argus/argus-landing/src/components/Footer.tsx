const PRODUCT_LINKS = ['Scan Engine', 'Agent Crew', 'Blockchain Anchor', 'API Docs'];
const COMPANY_LINKS = ['About', 'Security', 'Careers', 'Contact'];
const BADGES = ['SOC2', 'ISO27001', 'CVSS v3.1'];

function ArgusLogoSmall() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L21.5 7.5V16.5L12 22L2.5 16.5V7.5L12 2Z" fill="var(--green)" opacity="0.9" />
      <path d="M6 12C6 12 9 8.5 12 8.5C15 8.5 18 12 18 12C18 12 15 15.5 12 15.5C9 15.5 6 12 6 12Z" fill="#080A0F" opacity="0.85" />
      <circle cx="12" cy="12" r="2.2" fill="var(--green)" />
      <circle cx="12" cy="12" r="1" fill="#080A0F" />
    </svg>
  );
}

export default function Footer() {
  const linkStyle: React.CSSProperties = {
    fontFamily: "'DM Sans', sans-serif",
    fontSize: 13,
    color: 'var(--text-secondary)',
    textDecoration: 'none',
    transition: 'color 200ms ease',
    display: 'block',
    padding: '3px 0',
    cursor: 'pointer',
  };

  return (
    <footer style={{
      borderTop: '1px solid var(--border)',
      padding: '48px 40px 32px',
    }}>
      <div style={{ maxWidth: 1400, margin: '0 auto' }}>
        {/* Main row */}
        <div
          className="footer-main"
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr 1fr',
            gap: 40,
            marginBottom: 40,
          }}
        >
          {/* Left: Logo + tagline */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <ArgusLogoSmall />
              <span style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontWeight: 700,
                fontSize: 16,
                color: 'var(--text-primary)',
              }}>
                AR
                <span style={{
                  display: 'inline-block',
                  width: 4,
                  height: 4,
                  borderRadius: '50%',
                  background: 'var(--green)',
                  margin: '0 1px',
                  verticalAlign: 'middle',
                  position: 'relative',
                  top: -1,
                }} />
                GUS
              </span>
            </div>
            <p style={{
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 13,
              color: 'var(--text-muted)',
              lineHeight: 1.5,
            }}>
              Six agents. Zero blind spots.
            </p>
          </div>

          {/* Center: Link columns */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
            <div>
              <div style={{
                fontFamily: "'DM Sans', sans-serif",
                fontSize: 12,
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginBottom: 12,
                fontWeight: 600,
              }}>
                Product
              </div>
              {PRODUCT_LINKS.map((link) => (
                <a
                  key={link}
                  href="#"
                  style={linkStyle}
                  onMouseEnter={(e) => { (e.target as HTMLElement).style.color = 'var(--text-primary)'; }}
                  onMouseLeave={(e) => { (e.target as HTMLElement).style.color = 'var(--text-secondary)'; }}
                >
                  {link}
                </a>
              ))}
            </div>
            <div>
              <div style={{
                fontFamily: "'DM Sans', sans-serif",
                fontSize: 12,
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginBottom: 12,
                fontWeight: 600,
              }}>
                Company
              </div>
              {COMPANY_LINKS.map((link) => (
                <a
                  key={link}
                  href="#"
                  style={linkStyle}
                  onMouseEnter={(e) => { (e.target as HTMLElement).style.color = 'var(--text-primary)'; }}
                  onMouseLeave={(e) => { (e.target as HTMLElement).style.color = 'var(--text-secondary)'; }}
                >
                  {link}
                </a>
              ))}
            </div>
          </div>

          {/* Right: Trust badges */}
          <div>
            <p style={{
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 13,
              color: 'var(--text-secondary)',
              marginBottom: 16,
              lineHeight: 1.5,
            }}>
              Built for hackers. Trusted by compliance.
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {BADGES.map((badge) => (
                <span
                  key={badge}
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    background: 'var(--bg-panel)',
                    border: '1px solid var(--border)',
                    padding: '4px 10px',
                    borderRadius: 4,
                  }}
                >
                  {badge}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom row */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          paddingTop: 20,
          borderTop: '1px solid var(--border)',
          flexWrap: 'wrap',
          gap: 8,
        }}>
          <span style={{
            fontFamily: "'DM Sans', sans-serif",
            fontSize: 12,
            color: 'var(--text-muted)',
          }}>
            © 2024 Argus Security, Inc.
          </span>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12,
            color: 'var(--green)',
          }}>
            Made with 6 AI agents
          </span>
        </div>
      </div>

      {/* Responsive */}
      <style>{`
        @media (max-width: 768px) {
          .footer-main {
            grid-template-columns: 1fr !important;
            gap: 32px !important;
          }
        }
      `}</style>
    </footer>
  );
}
