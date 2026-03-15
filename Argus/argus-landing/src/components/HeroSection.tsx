import { useState, useEffect, useRef, useCallback } from 'react';

/* ── Typewriter lines for the hero terminal ── */
const TERMINAL_LINES = [
  { text: '$ argus scan --target https://target.acme.com --mode full', color: 'var(--green)' },
  { text: '[00:00:01] Initializing agent crew...', color: 'var(--text-muted)' },
  { text: '[00:00:02] Recon          → Mapping attack surface', color: 'var(--text-secondary)' },
  { text: '[00:00:05] Web Exploiter  → SSTI detected in /search?q=', color: 'var(--amber)' },
  { text: '[00:00:07] Net Exploiter  → PostgreSQL exposed on :5432', color: '#F97316' },
  { text: '[00:00:09] CVE Engine     → CVE-2024-3094 CVSS 9.8 CRITICAL', color: 'var(--red)' },
  { text: '[00:00:11] Chainer        → SSTI → RCE → DB pivot chain found', color: 'var(--purple)' },
  { text: '[00:00:14] Report         → Patches generated ✓', color: 'var(--green)' },
];

/* ── Argus Logo SVG (hexagon eye) ── */
function ArgusLogoLarge({ size = 72 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M12 2L21.5 7.5V16.5L12 22L2.5 16.5V7.5L12 2Z" fill="var(--green)" opacity="0.9" />
      <path d="M6 12C6 12 9 8.5 12 8.5C15 8.5 18 12 18 12C18 12 15 15.5 12 15.5C9 15.5 6 12 6 12Z" fill="#080A0F" opacity="0.85" />
      <circle cx="12" cy="12" r="2.2" fill="var(--green)" />
      <circle cx="12" cy="12" r="1" fill="#080A0F" />
    </svg>
  );
}

export default function HeroSection({ onStartScan }: { onStartScan: () => void }) {
  const [typedLines, setTypedLines] = useState<{ text: string; color: string }[]>([]);
  const [typingDone, setTypingDone] = useState(false);
  const [scrollY, setScrollY] = useState(0);
  const [scrollIndicatorVisible, setScrollIndicatorVisible] = useState(true);
  const [mounted, setMounted] = useState(false);
  const [mousePos, setMousePos] = useState({ x: 0.5, y: 0.5 });
  const typingRef = useRef(false);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => { setMounted(true); }, []);

  // Smooth scroll tracking
  useEffect(() => {
    const onScroll = () => {
      setScrollY(window.scrollY);
      setScrollIndicatorVisible(window.scrollY < 100);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  // Mouse tracking for subtle glow
  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!sectionRef.current) return;
    const rect = sectionRef.current.getBoundingClientRect();
    setMousePos({
      x: (e.clientX - rect.left) / rect.width,
      y: (e.clientY - rect.top) / rect.height,
    });
  }, []);

  // Typewriter
  const startTyping = useCallback(() => {
    if (typingRef.current) return;
    typingRef.current = true;
    let lineIdx = 0;
    let charIdx = 0;

    function tick() {
      if (lineIdx >= TERMINAL_LINES.length) { setTypingDone(true); return; }
      const line = TERMINAL_LINES[lineIdx];
      charIdx++;
      setTypedLines((prev) => {
        const copy = [...prev];
        copy[lineIdx] = { text: line.text.slice(0, charIdx), color: line.color };
        return copy;
      });
      if (charIdx >= line.text.length) { lineIdx++; charIdx = 0; setTimeout(tick, 120); }
      else { setTimeout(tick, 15); }
    }
    setTimeout(tick, 200);
  }, []);

  useEffect(() => {
    const timer = setTimeout(startTyping, 800);
    return () => clearTimeout(timer);
  }, [startTyping]);

  /* ── Scroll-driven transforms ── */
  const titleParallax = scrollY * 0.35;
  const titleScale = Math.max(0.85, 1 - scrollY / 4000);

  // Subtle tilt
  const tiltX = (mousePos.y - 0.5) * -4;
  const tiltY = (mousePos.x - 0.5) * 4;

  const TITLE = 'ARGUS';

  return (
    <section
      id="hero"
      ref={sectionRef}
      onMouseMove={handleMouseMove}
      style={{
        position: 'relative',
        height: '100vh',
        minHeight: 750,
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      {/* ── Grid background with parallax ── */}
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        backgroundPositionY: scrollY * 0.2,
        opacity: 0.3,
        pointerEvents: 'none',
      }} />

      {/* ── Subtle mouse-follow glow (replaces green orbs) ── */}
      <div style={{
        position: 'absolute', inset: 0,
        background: `radial-gradient(ellipse 500px 350px at ${mousePos.x * 100}% ${mousePos.y * 100}%, rgba(0,229,160,0.04) 0%, transparent 70%)`,
        pointerEvents: 'none',
        transition: 'background 0.4s ease',
      }} />

      {/* ── Main content with scroll parallax ── */}
      <div style={{
        position: 'relative', zIndex: 2,
        textAlign: 'center',
        maxWidth: 1100,
        padding: '0 24px',
        transform: `translateY(${titleParallax}px) scale(${titleScale})`,
        willChange: 'transform',
      }}>

        {/* ── Logo + Badge row ── */}
        <div style={{
          display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 14,
          marginBottom: 36,
          opacity: mounted ? 1 : 0,
          transform: mounted ? 'translateY(0)' : 'translateY(20px)',
          transition: 'opacity 0.6s ease 0.1s, transform 0.6s ease 0.1s',
        }}>
          <div style={{ position: 'relative', width: 72, height: 72 }}>
            <div style={{
              position: 'absolute', inset: -6,
              border: '1.5px solid transparent',
              borderTopColor: 'var(--green)',
              borderRightColor: 'rgba(0,229,160,0.3)',
              borderRadius: '50%',
              animation: 'hero-logo-spin 6s linear infinite',
            }} />
            <div style={{
              position: 'absolute', inset: -12,
              border: '1px solid transparent',
              borderBottomColor: 'rgba(0,229,160,0.15)',
              borderRadius: '50%',
              animation: 'hero-logo-spin 10s linear infinite reverse',
            }} />
            <ArgusLogoLarge size={72} />
          </div>

          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12,
            color: 'var(--green)',
            background: 'var(--green-dim)',
            border: '1px solid var(--border-glow)',
            padding: '6px 16px',
            borderRadius: 100,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
          }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: 'var(--green)',
              animation: 'pulse-dot 2s ease-in-out infinite',
            }} />
            AI-POWERED PENTESTING
          </span>
        </div>

        {/* ── Big ARGUS title — letter-by-letter ── */}
        <div style={{ perspective: 800, marginBottom: 24 }}>
          <h1
            style={{
              margin: 0,
              lineHeight: 0.9,
              transform: `rotateX(${tiltX}deg) rotateY(${tiltY}deg)`,
              transition: 'transform 0.2s ease-out',
              display: 'inline-block',
              position: 'relative',
            }}
          >
            {TITLE.split('').map((letter, i) => (
              <span
                key={i}
                className="hero-letter"
                style={{
                  fontFamily: "'Orbitron', sans-serif",
                  fontSize: i === 0 ? 'clamp(100px, 20vw, 220px)' : 'clamp(80px, 16vw, 180px)',
                  fontWeight: 900,
                  letterSpacing: '0.06em',
                  display: 'inline-block',
                  color: 'var(--text-primary)',
                  animation: mounted
                    ? `hero-letter-in 0.7s cubic-bezier(0.16, 1, 0.3, 1) ${0.15 + i * 0.1}s both`
                    : 'none',
                  transition: 'text-shadow 0.3s ease',
                }}
              >
                {letter}
              </span>
            ))}
          </h1>
        </div>

        {/* ── Tagline ── */}
        <p style={{
          fontFamily: "'Orbitron', sans-serif",
          fontSize: 'clamp(13px, 2.2vw, 18px)',
          fontWeight: 500,
          letterSpacing: '0.35em',
          textTransform: 'uppercase',
          color: 'var(--green)',
          marginBottom: 20,
          opacity: mounted ? 1 : 0,
          animation: mounted ? 'hero-subtitle-in 0.6s ease 0.9s both' : 'none',
        }}>
          Autonomous Penetration Testing
        </p>

        {/* ── Subheading ── */}
        <p style={{
          fontFamily: "'DM Sans', sans-serif",
          fontSize: 'clamp(15px, 2vw, 19px)',
          color: 'var(--text-secondary)',
          maxWidth: 600,
          margin: '0 auto 36px',
          lineHeight: 1.7,
          opacity: mounted ? 1 : 0,
          animation: mounted ? 'hero-subtitle-in 0.6s ease 1.1s both' : 'none',
        }}>
          Six AI agents work in coordinated sequence to discover attack chains,
          exploit vulnerabilities, and generate verified patches — automatically.
        </p>

        {/* ── CTA buttons ── */}
        <div style={{
          display: 'flex', justifyContent: 'center', gap: 14, flexWrap: 'wrap',
          opacity: mounted ? 1 : 0,
          animation: mounted ? 'hero-subtitle-in 0.6s ease 1.3s both' : 'none',
        }}>
          <button
            className="hero-cta-primary"
            onClick={onStartScan}
            style={{
              fontFamily: "'Orbitron', sans-serif",
              fontSize: 14, fontWeight: 700, letterSpacing: '0.08em',
              color: '#080A0F', background: 'var(--green)',
              border: 'none', padding: '14px 36px', borderRadius: 8,
              cursor: 'pointer', transition: 'transform 0.25s ease, box-shadow 0.25s ease',
              boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
            }}
          >
            RUN YOUR FIRST SCAN →
          </button>
          <button
            className="hero-cta-ghost"
            style={{
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 14, fontWeight: 500,
              color: 'var(--text-secondary)',
              background: 'transparent',
              border: '1px solid var(--border)',
              padding: '14px 28px', borderRadius: 8,
              cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 8,
              transition: 'border-color 0.25s ease, color 0.25s ease',
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="8,5 19,12 8,19" />
            </svg>
            Watch Demo
          </button>
        </div>

        {/* ── Sub-CTA hint ── */}
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 12, color: 'var(--text-muted)', marginTop: 14,
          opacity: mounted ? 1 : 0,
          animation: mounted ? 'hero-subtitle-in 0.5s ease 1.5s both' : 'none',
        }}>
          ↳ No installation required · Runs in your browser
        </p>

        {/* ── Terminal preview ── */}
        <div
          className="hero-terminal"
          style={{
            maxWidth: 620, margin: '48px auto 0',
            background: 'rgba(13,17,23,0.8)',
            border: '1px solid var(--border)',
            borderRadius: 14, padding: '18px 22px', textAlign: 'left',
            backdropFilter: 'blur(20px)',
            transition: 'border-color 0.3s ease, box-shadow 0.3s ease',
            opacity: mounted ? 1 : 0,
            animation: mounted ? 'hero-subtitle-in 0.6s ease 1.6s both' : 'none',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#555', opacity: 0.5 }} />
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#555', opacity: 0.5 }} />
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#555', opacity: 0.5 }} />
            </div>
            <span style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11, color: 'var(--text-muted)', margin: '0 auto',
            }}>
              argus — zsh
            </span>
            <div style={{ width: 42 }} />
          </div>

          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, lineHeight: 1.7 }}>
            {typedLines.map((line, i) => (
              <div key={i} style={{ color: line.color, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {line.text}
              </div>
            ))}
            {typedLines.length > 0 && (
              <span style={{
                display: 'inline-block', width: 8, height: 15,
                background: 'var(--green)',
                animation: 'blink-cursor 1s step-end infinite',
                verticalAlign: 'text-bottom',
                marginTop: typingDone ? 4 : 0,
              }} />
            )}
          </div>
        </div>
      </div>

      {/* ── Scroll indicator ── */}
      <div style={{
        position: 'absolute', bottom: 28, left: '50%',
        transform: 'translateX(-50%)', textAlign: 'center',
        opacity: scrollIndicatorVisible ? 1 : 0,
        transition: 'opacity 400ms ease', pointerEvents: 'none',
      }}>
        <span style={{
          fontFamily: "'DM Sans', sans-serif",
          fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4,
        }}>
          scroll to explore
        </span>
        <span style={{
          fontSize: 16, color: 'var(--text-muted)', display: 'block',
          animation: 'bob 2s ease-in-out infinite',
        }}>
          ↓
        </span>
      </div>

      {/* ── Hover styles ── */}
      <style>{`
        .hero-letter:hover {
          text-shadow: 0 0 30px rgba(0,229,160,0.4), 0 0 60px rgba(0,229,160,0.15) !important;
        }
        .hero-cta-primary:hover {
          transform: translateY(-2px) !important;
          box-shadow: 0 0 40px rgba(0,229,160,0.25), 0 8px 30px rgba(0,0,0,0.4) !important;
        }
        .hero-cta-ghost:hover {
          border-color: var(--border-glow) !important;
          color: var(--text-primary) !important;
        }
        .hero-terminal:hover {
          border-color: var(--border-glow) !important;
          box-shadow: 0 0 40px rgba(0,229,160,0.04), 0 20px 60px rgba(0,0,0,0.3) !important;
        }
      `}</style>
    </section>
  );
}
