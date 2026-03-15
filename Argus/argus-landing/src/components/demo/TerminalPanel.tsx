import { useEffect, useRef } from 'react';
import type { AgentLog } from '../../types';

const AGENT_COLORS: Record<string, string> = {
  Master: 'var(--text-muted)',
  Recon: '#0EA5E9',
  'Web Exploiter': 'var(--amber)',
  'Net Exploiter': '#F97316',
  'CVE Engine': 'var(--red)',
  Chainer: 'var(--purple)',
  Report: 'var(--green)',
};

export default function TerminalPanel({ logs }: { logs: AgentLog[] }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs.length]);

  return (
    <div ref={containerRef} style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      padding: '14px 18px',
      height: 280,
      overflowY: 'auto',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 11,
      lineHeight: 1.7,
    }}>
      {/* Traffic light dots */}
      <div style={{ display: 'flex', gap: 5, marginBottom: 12 }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#FF5F57' }} />
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#FFBD2E' }} />
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#28C840' }} />
      </div>

      {logs.map((log, i) => (
        <div
          key={i}
          style={{
            opacity: 0,
            animation: 'fadeSlideIn 0.3s ease-out forwards',
            animationDelay: `${i * 60}ms`,
          }}
        >
          <span style={{ color: 'var(--text-muted)' }}>[{log.timestamp}] </span>
          <span style={{ color: AGENT_COLORS[log.agent] || 'var(--text-secondary)' }}>
            {log.agent}
          </span>
          <span style={{ color: 'var(--text-muted)' }}> → </span>
          <span style={{ color: 'var(--text-secondary)' }}>{log.message}</span>
        </div>
      ))}

      {logs.length > 0 && (
        <span style={{
          display: 'inline-block',
          width: 6,
          height: 12,
          background: 'var(--green)',
          animation: 'blink-cursor 1s step-end infinite',
          marginTop: 4,
        }} />
      )}

      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
