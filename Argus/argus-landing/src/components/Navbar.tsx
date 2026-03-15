import { useState, useEffect } from 'react';

const NAV_LINKS = [
  { label: 'Home', href: '#hero' },
  { label: 'How it Works', href: '#how-it-works' },
  { label: 'Why Argus', href: '#why-argus' },
  { label: 'Demo', href: '#demo' },
  { label: 'Trust', href: '#trust' },
];

/* ── Inline SVG: Argus hexagon eye logo ── */
function ArgusLogo() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      {/* Hexagon */}
      <path
        d="M12 2L21.5 7.5V16.5L12 22L2.5 16.5V7.5L12 2Z"
        fill="var(--green)"
        opacity="0.9"
      />
      {/* Eye shape — two arcs forming an iris */}
      <path
        d="M6 12C6 12 9 8.5 12 8.5C15 8.5 18 12 18 12C18 12 15 15.5 12 15.5C9 15.5 6 12 6 12Z"
        fill="#080A0F"
        opacity="0.85"
      />
      {/* Iris */}
      <circle cx="12" cy="12" r="2.2" fill="var(--green)" />
      {/* Pupil */}
      <circle cx="12" cy="12" r="1" fill="#080A0F" />
    </svg>
  );
}

/* ── Hamburger icon ── */
function HamburgerIcon({ open }: { open: boolean }) {
  const bar: React.CSSProperties = {
    display: 'block',
    width: 18,
    height: 1.5,
    background: 'var(--text-primary)',
    borderRadius: 1,
    transition: 'transform 200ms ease, opacity 200ms ease',
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, cursor: 'pointer' }}>
      <span style={{ ...bar, transform: open ? 'rotate(45deg) translate(3px, 3px)' : 'none' }} />
      <span style={{ ...bar, opacity: open ? 0 : 1 }} />
      <span style={{ ...bar, transform: open ? 'rotate(-45deg) translate(3px, -3px)' : 'none' }} />
    </div>
  );
}

export default function Navbar({ onStartScan }: { onStartScan: () => void }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [activeLink, setActiveLink] = useState('');

  // Track active section via IntersectionObserver
  useEffect(() => {
    const ids = ['hero', 'how-it-works', 'why-argus', 'demo', 'trust'];
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveLink('#' + entry.target.id);
          }
        });
      },
      { rootMargin: '-40% 0px -50% 0px' }
    );

    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, []);

  const navStyle: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    height: 64,
    zIndex: 1000,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 32px',
    borderBottom: '1px solid var(--border)',
    background: 'rgba(8,10,15,0.95)',
    backdropFilter: 'blur(20px) saturate(180%)',
    WebkitBackdropFilter: 'blur(20px) saturate(180%)',
  };

  const linkStyle = (href: string): React.CSSProperties => ({
    fontFamily: "'DM Sans', sans-serif",
    fontSize: 14,
    color: activeLink === href ? 'var(--text-primary)' : 'var(--text-secondary)',
    textDecoration: 'none',
    position: 'relative',
    padding: '6px 0',
    transition: 'color 200ms ease',
    borderBottom: activeLink === href ? '2px solid var(--green)' : '2px solid transparent',
  });

  const ghostBtn: React.CSSProperties = {
    fontFamily: "'DM Sans', sans-serif",
    fontSize: 13,
    color: 'var(--text-secondary)',
    background: 'transparent',
    border: '1px solid var(--border)',
    padding: '8px 18px',
    borderRadius: 6,
    cursor: 'pointer',
    transition: 'border-color 200ms ease, background 200ms ease, color 200ms ease',
  };

  const primaryBtn: React.CSSProperties = {
    fontFamily: "'DM Sans', sans-serif",
    fontSize: 13,
    fontWeight: 600,
    color: '#080A0F',
    background: 'var(--green)',
    border: 'none',
    padding: '8px 20px',
    borderRadius: 6,
    cursor: 'pointer',
    transition: 'filter 200ms ease, transform 200ms ease',
    animation: 'pulse-glow 3s ease-in-out infinite',
  };

  const mobileDrawerStyle: React.CSSProperties = {
    position: 'fixed',
    top: 64,
    left: 0,
    right: 0,
    background: 'rgba(8,10,15,0.95)',
    backdropFilter: 'blur(20px)',
    borderBottom: '1px solid var(--border)',
    padding: '16px 24px',
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
    zIndex: 999,
    transform: mobileOpen ? 'translateY(0)' : 'translateY(-100%)',
    opacity: mobileOpen ? 1 : 0,
    transition: 'transform 300ms ease, opacity 300ms ease',
    pointerEvents: mobileOpen ? 'auto' : 'none',
  };

  return (
    <>
      <nav style={navStyle}>
        {/* ── Left: Logo ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ArgusLogo />
          <span style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontWeight: 700,
            fontSize: 18,
            color: 'var(--text-primary)',
            letterSpacing: '-0.01em',
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
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            color: 'var(--green)',
            background: 'var(--green-dim)',
            border: '1px solid var(--border-glow)',
            borderRadius: 4,
            padding: '2px 6px',
            marginLeft: 4,
          }}>
            BETA
          </span>
        </div>

        {/* ── Center: Nav links (desktop) ── */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 32,
        }}
          className="nav-links-desktop"
        >
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              style={linkStyle(link.href)}
              onMouseEnter={(e) => {
                (e.target as HTMLElement).style.color = 'var(--text-primary)';
              }}
              onMouseLeave={(e) => {
                if (activeLink !== link.href) {
                  (e.target as HTMLElement).style.color = 'var(--text-secondary)';
                }
              }}
            >
              {link.label}
            </a>
          ))}
        </div>

        {/* ── Right: Buttons (desktop) ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}
          className="nav-btns-desktop"
        >
          <button
            style={ghostBtn}
            onMouseEnter={(e) => {
              const el = e.currentTarget;
              el.style.borderColor = 'var(--border-glow)';
              el.style.background = 'var(--green-dim)';
              el.style.color = 'var(--text-primary)';
            }}
            onMouseLeave={(e) => {
              const el = e.currentTarget;
              el.style.borderColor = 'var(--border)';
              el.style.background = 'transparent';
              el.style.color = 'var(--text-secondary)';
            }}
          >
            View Docs
          </button>
          <button
            style={primaryBtn}
            onClick={onStartScan}
            onMouseEnter={(e) => {
              e.currentTarget.style.filter = 'brightness(1.1)';
              e.currentTarget.style.transform = 'scale(1.02)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.filter = 'none';
              e.currentTarget.style.transform = 'scale(1)';
            }}
          >
            Start Scan →
          </button>
        </div>

        {/* ── Mobile hamburger ── */}
        <div
          className="nav-hamburger"
          style={{ display: 'none' }}
          onClick={() => setMobileOpen((o) => !o)}
        >
          <HamburgerIcon open={mobileOpen} />
        </div>
      </nav>

      {/* ── Mobile drawer ── */}
      <div style={mobileDrawerStyle} className="nav-mobile-drawer">
        {NAV_LINKS.map((link) => (
          <a
            key={link.href}
            href={link.href}
            onClick={() => setMobileOpen(false)}
            style={{
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 15,
              color: 'var(--text-secondary)',
              textDecoration: 'none',
              padding: '8px 0',
            }}
          >
            {link.label}
          </a>
        ))}
        <button
          style={{ ...primaryBtn, width: '100%', padding: '10px 0', marginTop: 8 }}
          onClick={() => { setMobileOpen(false); onStartScan(); }}
        >
          Start Scan →
        </button>
      </div>

      {/* ── Responsive CSS (injected once) ── */}
      <style>{`
        @media (max-width: 768px) {
          .nav-links-desktop { display: none !important; }
          .nav-btns-desktop { display: none !important; }
          .nav-hamburger { display: flex !important; }
        }
      `}</style>
    </>
  );
}
