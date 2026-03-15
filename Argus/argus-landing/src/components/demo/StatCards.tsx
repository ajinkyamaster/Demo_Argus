import type { ScanSummary } from '../../types';
import { useCountUp } from '../../hooks/useCountUp';

const METER_CELLS = [
  { label: 'TOTAL FINDINGS', key: 'total',    accent: 'var(--text-primary)',  glow: '' },
  { label: 'CRITICAL',       key: 'critical', accent: 'var(--red)',            glow: 'rgba(255,59,59,0.3)' },
  { label: 'HIGH',           key: 'high',     accent: 'var(--amber)',          glow: 'rgba(245,158,11,0.3)' },
  { label: 'MAX CVSS',       key: 'cvss',     accent: 'var(--red)',            glow: 'rgba(255,59,59,0.18)' },
  { label: 'SCAN TIME',      key: 'elapsed',  accent: 'var(--green)',          glow: 'rgba(0,229,160,0.15)' },
];

export default function StatCards({ summary, active }: { summary: ScanSummary; active: boolean }) {
  const total    = useCountUp(summary.total_findings, 1200, active);
  const critical = useCountUp(summary.critical_count, 1200, active);
  const high     = useCountUp(summary.high_count, 1200, active);
  const cvss     = useCountUp(summary.max_cvss, 1400, active, 1);

  const values: Record<string, string | number> = {
    total,
    critical,
    high,
    cvss,
    elapsed: summary.scan_duration,
  };
  const units: Record<string, string> = {
    cvss: '/10',
  };

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: `repeat(${METER_CELLS.length}, 1fr)`,
      flex: 1,
      minWidth: 0,
      background: 'var(--border)',
      gap: 1,
      borderRadius: 6,
      overflow: 'hidden',
    }}
      className="stat-meter-grid"
    >
      {METER_CELLS.map((cell, i) => (
        <div
          key={cell.key}
          style={{
            background: 'var(--bg-surface)',
            padding: '18px 16px',
            textAlign: 'center',
            opacity: active ? 1 : 0,
            transform: active ? 'translateY(0)' : 'translateY(10px)',
            transition: `opacity 0.4s ease ${i * 70}ms, transform 0.4s ease ${i * 70}ms`,
          }}
        >
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 8,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.12em',
            marginBottom: 10,
          }}>
            {cell.label}
          </div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 26,
            fontWeight: 700,
            color: cell.accent,
            lineHeight: 1,
            textShadow: cell.glow ? `0 0 20px ${cell.glow}` : 'none',
          }}>
            {values[cell.key]}
            {units[cell.key] && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>
                {units[cell.key]}
              </span>
            )}
          </div>
        </div>
      ))}

      <style>{`
        @media (max-width: 700px) {
          .stat-meter-grid {
            grid-template-columns: repeat(3, 1fr) !important;
          }
        }
        @media (max-width: 480px) {
          .stat-meter-grid {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
      `}</style>
    </div>
  );
}
