import { useState } from 'react';
import type { Vulnerability, Severity } from '../../types';

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: 'var(--red)',
  HIGH: 'var(--amber)',
  MEDIUM: 'var(--blue)',
  LOW: 'var(--green)',
};

const SEV_BG: Record<Severity, string> = {
  CRITICAL: 'var(--red-dim)',
  HIGH: 'rgba(245,158,11,0.1)',
  MEDIUM: 'rgba(59,130,246,0.1)',
  LOW: 'var(--green-dim)',
};

function FindingCard({ vuln, index }: { vuln: Vulnerability; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const color = SEV_COLORS[vuln.severity];
  const isCritical = vuln.severity === 'CRITICAL';
  const hasPatch = vuln.patch_code !== null;

  return (
    <div
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${color}`,
        borderRadius: 10,
        padding: 24,
        opacity: 0,
        transform: 'translateY(16px)',
        animation: `cardIn 0.4s ease-out ${index * 100}ms forwards${isCritical ? `, critPulse 0.8s ease-out ${index * 100 + 200}ms 1` : ''}`,
        transition: 'border-color 200ms ease, box-shadow 200ms ease',
        cursor: hasPatch ? 'pointer' : 'default',
      }}
      onClick={() => { if (hasPatch) setExpanded(!expanded); }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = color;
        e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,0,0,0.3)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--border)';
        e.currentTarget.style.borderLeftColor = color;
        e.currentTarget.style.boxShadow = 'none';
      }}
    >
      {/* Top row: severity badge + CVE */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 8,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            fontWeight: 600,
            color: color,
            background: SEV_BG[vuln.severity],
            padding: '3px 8px',
            borderRadius: 4,
            textTransform: 'uppercase',
          }}>
            {vuln.severity}
          </span>
          {hasPatch && (
            <span style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 9,
              color: 'var(--green)',
              background: 'var(--green-dim)',
              padding: '2px 6px',
              borderRadius: 3,
            }}>
              PATCH AVAILABLE
            </span>
          )}
        </div>
        {vuln.cve_ids.length > 0 && (
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            color: 'var(--text-muted)',
          }}>
            {vuln.cve_ids[0]}
          </span>
        )}
      </div>

      {/* Title */}
      <div style={{
        fontFamily: "'DM Sans', sans-serif",
        fontSize: 14,
        fontWeight: 500,
        color: 'var(--text-primary)',
        marginBottom: 6,
        lineHeight: 1.3,
      }}>
        {vuln.title}
      </div>

      {/* Description — show full when expanded */}
      <div style={{
        fontFamily: "'DM Sans', sans-serif",
        fontSize: 12,
        color: 'var(--text-secondary)',
        lineHeight: 1.5,
        marginBottom: 10,
        ...(expanded ? {} : {
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical' as const,
          overflow: 'hidden',
        }),
      }}>
        {vuln.description}
      </div>

      {/* Bottom row: CVSS pill + component + expand hint */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            fontWeight: 600,
            color: color,
          }}>
            {vuln.cvss_score.toFixed(1)}
          </span>
          <div style={{
            width: 40,
            height: 4,
            borderRadius: 2,
            background: 'var(--bg-panel)',
            overflow: 'hidden',
          }}>
            <div style={{
              width: `${(vuln.cvss_score / 10) * 100}%`,
              height: '100%',
              background: color,
              borderRadius: 2,
            }} />
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            color: 'var(--text-muted)',
          }}>
            {vuln.affected_component}
          </span>
          {hasPatch && (
            <span style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: 'var(--text-muted)',
              transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
              transition: 'transform 200ms ease',
              display: 'inline-block',
            }}>
              ▼
            </span>
          )}
        </div>
      </div>

      {/* ── Expandable patch code section ── */}
      {expanded && vuln.patch_code && (
        <div style={{
          marginTop: 16,
          paddingTop: 16,
          borderTop: '1px solid var(--border)',
        }}>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            color: 'var(--text-muted)',
            marginBottom: 12,
          }}>
            {vuln.patch_code.file_path}
          </div>

          {/* Vulnerable code */}
          <div style={{ marginBottom: 12 }}>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: 'var(--red)',
              marginBottom: 6,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>
              Vulnerable
            </div>
            <pre style={{
              background: 'rgba(255,59,59,0.06)',
              border: '1px solid rgba(255,59,59,0.15)',
              borderRadius: 8,
              padding: '12px 16px',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              color: 'var(--text-primary)',
              lineHeight: 1.6,
              overflowX: 'auto',
              margin: 0,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}>
              {vuln.patch_code.vulnerable_snippet}
            </pre>
          </div>

          {/* Fixed code */}
          <div>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: 'var(--green)',
              marginBottom: 6,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>
              Fixed
            </div>
            <pre style={{
              background: 'rgba(0,229,160,0.06)',
              border: '1px solid rgba(0,229,160,0.15)',
              borderRadius: 8,
              padding: '12px 16px',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              color: 'var(--text-primary)',
              lineHeight: 1.6,
              overflowX: 'auto',
              margin: 0,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}>
              {vuln.patch_code.fixed_snippet}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

export default function FindingCards({ findings }: { findings: Vulnerability[] }) {
  return (
    <>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr',
          gap: 16,
        }}
        className="finding-cards-grid"
      >
        {findings.map((vuln, i) => (
          <FindingCard key={vuln.id} vuln={vuln} index={i} />
        ))}
      </div>

      <style>{`
        @keyframes cardIn {
          from { opacity: 0; transform: translateY(16px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes critPulse {
          0%   { box-shadow: 0 0 0 rgba(255,59,59,0); }
          50%  { box-shadow: 0 0 30px rgba(255,59,59,0.25); }
          100% { box-shadow: 0 0 0 rgba(255,59,59,0); }
        }
      `}</style>
    </>
  );
}
