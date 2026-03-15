import { useEffect, useRef, useState } from 'react';

function scoreColor(score: number): string {
  if (score >= 9) return '#EF4444';
  if (score >= 7) return '#F97316';
  if (score >= 5) return '#F59E0B';
  if (score >= 3) return '#00E5A0';
  return '#22D3EE';
}

function scoreLabel(score: number): string {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

export default function CvssDial({ score, active }: { score: number; active: boolean }) {
  const [displayScore, setDisplayScore] = useState(0);
  const [glowing, setGlowing] = useState(false);
  const frameRef = useRef<number>(0);

  // Arc geometry: 220 degrees, starts at ~210° (8 o'clock) ends at ~-30° (4 o'clock)
  const size = 160;
  const cx = size / 2;
  const cy = size / 2;
  const radius = 62;
  const strokeWidth = 10;
  const totalAngleDeg = 220;
  const startAngleDeg = 160; // start at 8 o'clock

  function polarToCartesian(angleDeg: number) {
    const rad = (angleDeg * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(rad),
      y: cy + radius * Math.sin(rad),
    };
  }

  function arcPath(fraction: number) {
    const endAngleDeg = startAngleDeg + totalAngleDeg * fraction;
    const start = polarToCartesian(startAngleDeg);
    const end = polarToCartesian(endAngleDeg);
    const largeArc = totalAngleDeg * fraction > 180 ? 1 : 0;
    return `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArc} 1 ${end.x} ${end.y}`;
  }

  // Track path (full arc background)
  const trackPath = arcPath(1);

  // Animate the score fill
  useEffect(() => {
    if (!active) {
      setDisplayScore(0);
      return;
    }

    const duration = 2800;
    const startTime = performance.now();

    function tick(now: number) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = eased * score;
      setDisplayScore(Number(current.toFixed(1)));

      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick);
      } else {
        // Glow effect when hitting >= 9.0
        if (score >= 9) {
          setGlowing(true);
          setTimeout(() => setGlowing(false), 1000);
        }
      }
    }

    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [active, score]);

  const fraction = displayScore / 10;
  const fillPath = arcPath(fraction);
  const color = scoreColor(displayScore);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      opacity: active ? 1 : 0,
      transform: active ? 'translateY(0)' : 'translateY(16px)',
      transition: 'opacity 0.5s ease-out, transform 0.5s ease-out',
    }}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        style={{
          filter: glowing ? `drop-shadow(0 0 12px rgba(255,59,59,0.5))` : 'none',
          transition: 'filter 0.5s ease-out',
        }}
      >
        {/* Track */}
        <path
          d={trackPath}
          stroke="var(--bg-panel)"
          strokeWidth={strokeWidth}
          fill="none"
          strokeLinecap="round"
        />
        {/* Fill */}
        <path
          d={fillPath}
          stroke={color}
          strokeWidth={strokeWidth}
          fill="none"
          strokeLinecap="round"
        />
        {/* Center score */}
        <text
          x={cx}
          y={cy - 4}
          textAnchor="middle"
          dominantBaseline="central"
          style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: 28,
            fontWeight: 700,
            fill: color,
          }}
        >
          {displayScore.toFixed(1)}
        </text>
        {/* Label */}
        <text
          x={cx}
          y={cy + 18}
          textAnchor="middle"
          dominantBaseline="central"
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            fill: color,
          }}
        >
          {scoreLabel(displayScore)}
        </text>
      </svg>
    </div>
  );
}
