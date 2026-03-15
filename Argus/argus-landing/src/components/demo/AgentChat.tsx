import { useEffect, useRef } from 'react';
import type { AgentLog } from '../../types';

const AGENT_CALLSIGNS: Record<string, string> = {
  Master: 'COMMAND',
  Recon: 'RECON-1',
  'Web Exploiter': 'WEB-OPS',
  'Net Exploiter': 'NET-OPS',
  'CVE Engine': 'INTEL',
  Chainer: 'CHAIN-X',
  Report: 'SIGINT',
};

const AGENT_COLORS: Record<string, string> = {
  Master: '#8B8B6E',
  Recon: '#0EA5E9',
  'Web Exploiter': 'var(--amber)',
  'Net Exploiter': '#F97316',
  'CVE Engine': 'var(--red)',
  Chainer: 'var(--purple)',
  Report: 'var(--green)',
};

export default function AgentChat({ logs }: { logs: AgentLog[] }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs.length]);

  if (logs.length === 0) {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: 200,
        gap: 12,
      }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: '#5C6B4F',
          textTransform: 'uppercase',
          letterSpacing: '0.15em',
        }}>
          AWAITING TRANSMISSIONS...
        </div>
        <div style={{
          width: 40,
          height: 2,
          background: '#3A4A2E',
          animation: 'scanline 1.5s ease-in-out infinite',
        }} />
      </div>
    );
  }

  return (
    <div ref={containerRef} style={{
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column',
      gap: 4,
      padding: '4px 0',
      height: '100%',
    }}>
      {logs.map((log, i) => {
        const isMaster = log.agent === 'Master';
        const callsign = AGENT_CALLSIGNS[log.agent] || log.agent;
        const color = AGENT_COLORS[log.agent] || '#5C6B4F';

        return (
          <div
            key={i}
            style={{
              opacity: 0,
              animation: `transIn 0.3s ease-out ${i * 60}ms forwards`,
              padding: '8px 12px',
              borderBottom: '1px solid rgba(90,110,70,0.1)',
            }}
          >
            {/* Transmission header line */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              marginBottom: 4,
            }}>
              {/* Signal indicator */}
              <span style={{
                display: 'inline-block',
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: color,
                boxShadow: `0 0 6px ${color}`,
                flexShrink: 0,
              }} />
              {/* Callsign */}
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                fontWeight: 700,
                color: color,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
              }}>
                {callsign}
              </span>
              {/* Classification */}
              {isMaster && (
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 8,
                  color: '#8B8B6E',
                  background: 'rgba(139,139,110,0.1)',
                  border: '1px solid rgba(139,139,110,0.2)',
                  padding: '1px 5px',
                  borderRadius: 2,
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                }}>
                  PRIORITY
                </span>
              )}
              {/* Timestamp */}
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: '#4A5A3E',
                marginLeft: 'auto',
                flexShrink: 0,
              }}>
                {log.timestamp}
              </span>
            </div>

            {/* Message body */}
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              color: isMaster ? '#A0A080' : '#C8D0B0',
              lineHeight: 1.65,
              paddingLeft: 14,
              fontStyle: isMaster ? 'normal' : 'normal',
            }}>
              {log.message}
            </div>
          </div>
        );
      })}

      <style>{`
        @keyframes transIn {
          from { opacity: 0; transform: translateX(-8px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes scanline {
          0%, 100% { opacity: 0.3; width: 40px; }
          50% { opacity: 1; width: 80px; }
        }
      `}</style>
    </div>
  );
}
