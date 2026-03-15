import { useState } from 'react';

/* ── SVG Icons ── */
function ShieldIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l8 4v6c0 5.5-3.8 8.2-8 10-4.2-1.8-8-4.5-8-10V6l8-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function ClockIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </svg>
  );
}

function VerifyIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <path d="M22 4L12 14.01l-3-3" />
    </svg>
  );
}

const VALUE_PROPS = [
  {
    Icon: ShieldIcon,
    title: 'Non-repudiation',
    desc: 'The report SHA-256 hash lives on-chain forever. No dispute about what was found and when.',
  },
  {
    Icon: ClockIcon,
    title: 'Immutable timestamp',
    desc: 'Block timestamp proves when each vulnerability was discovered. Backdating is impossible.',
  },
  {
    Icon: VerifyIcon,
    title: 'Vendor accountability',
    desc: 'Share the tx hash with clients. They verify the report independently. No trust required.',
  },
];

export default function BlockchainTrust() {
  const [copied, setCopied] = useState(false);

  const copyHash = () => {
    navigator.clipboard.writeText('0x8f3a2c9d1e4b7a0f2c6d8e1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b9');
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <section
      id="trust"
      style={{
        padding: '120px 0',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Green radial glow */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(ellipse at center, rgba(0,229,160,0.05) 0%, transparent 60%)',
        pointerEvents: 'none',
      }} />

      <div style={{ position: 'relative', maxWidth: 1400, margin: '0 auto', padding: '0 40px' }}>
        {/* Header */}
        <div className="reveal" data-delay="0" style={{ textAlign: 'center', marginBottom: 64 }}>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            color: 'var(--green)',
            marginBottom: 8,
          }}>
            // TRUST LAYER
          </p>
          <h2 style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: 'clamp(32px, 5vw, 48px)',
            fontWeight: 700,
            color: 'var(--text-primary)',
            margin: 0,
          }}>
            Every report. Cryptographically{' '}
            <span style={{ color: 'var(--green)' }}>sealed.</span>
          </h2>
          <p style={{
            fontFamily: "'DM Sans', sans-serif",
            fontSize: 18,
            color: 'var(--text-secondary)',
            marginTop: 16,
            maxWidth: 560,
            marginLeft: 'auto',
            marginRight: 'auto',
            lineHeight: 1.6,
          }}>
            Every scan report is hashed, timestamped, and anchored to a public blockchain.
            Immutable proof that the assessment happened — exactly when it happened.
          </p>
        </div>

        {/* Value props — 3 columns */}
        <div
          className="trust-props"
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: 40,
            marginBottom: 72,
          }}
        >
          {VALUE_PROPS.map((prop, i) => (
            <div
              key={i}
              className="reveal"
              data-delay={String(i * 100)}
              style={{ textAlign: 'center' }}
            >
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
                <prop.Icon />
              </div>
              <div style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 16,
                fontWeight: 600,
                color: 'var(--text-primary)',
                marginBottom: 8,
              }}>
                {prop.title}
              </div>
              <div style={{
                fontFamily: "'DM Sans', sans-serif",
                fontSize: 13,
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
              }}>
                {prop.desc}
              </div>
            </div>
          ))}
        </div>

        {/* ── Blockchain Anchor Demo Card ── */}
        <div
          className="reveal"
          data-delay="0"
          style={{
            maxWidth: 720,
            margin: '0 auto',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-glow)',
            boxShadow: '0 0 60px rgba(0,229,160,0.08)',
            borderRadius: 16,
            padding: 40,
            animation: 'border-glow-cycle 4s ease-in-out infinite',
          }}
        >
          {/* Label */}
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            color: 'var(--green)',
            textTransform: 'uppercase',
            letterSpacing: '0.15em',
            marginBottom: 16,
          }}>
            REPORT ANCHORED ON-CHAIN
          </div>

          {/* Confirmed badge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" fill="var(--green-dim)" stroke="var(--green)" strokeWidth="1.5" />
              <path d="M8 12l3 3 5-5" stroke="var(--green)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: 18,
              fontWeight: 600,
              color: 'var(--text-primary)',
            }}>
              Confirmed
            </span>
          </div>

          {/* Data rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 24 }}>
            {[
              { label: 'Report hash', value: '0x8f3a...e2b9' },
              { label: 'Block', value: '#18,847,293' },
              { label: 'Timestamp', value: '2024-01-15 · 14:23:07 UTC' },
              { label: 'Network', value: 'Ethereum Mainnet' },
            ].map((row, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 0',
                  borderBottom: i < 3 ? '1px solid var(--border)' : 'none',
                }}
              >
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 12,
                  color: 'var(--text-muted)',
                }}>
                  {row.label}
                </span>
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 12,
                  color: 'var(--text-primary)',
                }}>
                  {row.value}
                </span>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <button
              onClick={copyHash}
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12,
                color: copied ? 'var(--green)' : 'var(--text-secondary)',
                background: 'transparent',
                border: '1px solid var(--border)',
                padding: '6px 14px',
                borderRadius: 6,
                cursor: 'pointer',
                transition: 'border-color 200ms ease, color 200ms ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-glow)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
              }}
            >
              {copied ? 'Copied ✓' : 'Copy hash'}
            </button>
            <a
              href="#"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12,
                color: 'var(--green)',
                textDecoration: 'none',
                transition: 'opacity 200ms ease',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.8'; }}
              onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
            >
              Verify on Etherscan ↗
            </a>
          </div>

          {/* Separator + methodology blurb */}
          <div style={{
            marginTop: 24,
            paddingTop: 20,
            borderTop: '1px solid var(--border)',
          }}>
            <p style={{
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 12,
              color: 'var(--text-muted)',
              lineHeight: 1.6,
            }}>
              Report integrity is verified by computing the SHA-256 hash of the full JSON report
              and comparing it against the hash stored in the smart contract. Any modification
              to the report will produce a different hash, immediately detectable.
            </p>
          </div>
        </div>
      </div>

      {/* Responsive */}
      <style>{`
        @media (max-width: 640px) {
          .trust-props {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
