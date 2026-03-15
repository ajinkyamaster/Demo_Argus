import { useState, useEffect } from 'react';
import type { Severity } from '../../types';

export interface SeveritySegment {
  severity: Severity;
  count: number;
}

const SEV_COLORS: Record<Severity, string> = {
  LOW: 'var(--green)',
  MEDIUM: 'var(--blue)',
  HIGH: 'var(--amber)',
  CRITICAL: 'var(--red)',
};

export default function SeverityBar({
  segments,
  flash,
}: {
  segments: SeveritySegment[];
  flash?: boolean;
}) {
  const [animatedFlash, setAnimatedFlash] = useState(false);

  useEffect(() => {
    if (flash) {
      setAnimatedFlash(true);
      const t = setTimeout(() => setAnimatedFlash(false), 200);
      return () => clearTimeout(t);
    }
  }, [flash]);

  const total = segments.reduce((acc, s) => acc + s.count, 0);

  return (
    <div style={{
      width: '100%',
      height: 6,
      borderRadius: 3,
      background: 'var(--bg-panel)',
      overflow: 'hidden',
      position: 'relative',
      animation: animatedFlash ? 'critical-flash 200ms ease-out 1' : 'none',
    }}>
      <div style={{ display: 'flex', height: '100%' }}>
        {segments.map((seg, i) => {
          const pct = total > 0 ? (seg.count / total) * 100 : 0;
          return (
            <div
              key={i}
              style={{
                width: `${pct}%`,
                background: SEV_COLORS[seg.severity],
                transition: 'width 400ms ease-out',
                height: '100%',
              }}
            />
          );
        })}
      </div>
    </div>
  );
}
