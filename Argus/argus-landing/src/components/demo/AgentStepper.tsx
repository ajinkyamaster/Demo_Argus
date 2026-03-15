import type { AgentStep } from '../../types';

const AGENT_META: Record<string, string> = {
  Recon: 'Network & surface mapping',
  'Web Exploiter': 'SQLi, XSS, SSTI, LFI',
  'Net Exploiter': 'Network-layer probing',
  'CVE Engine': 'CVE mapping & CVSS scoring',
  Chainer: 'Attack chain analysis',
  Report: 'Report & patch generation',
};

export default function AgentStepper({ agents }: { agents: AgentStep[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {agents.map((agent, i) => {
        const isActive = agent.status === 'active';
        const isDone = agent.status === 'done';
        const isError = agent.status === 'error';

        const dotColor = isDone || isActive
          ? 'var(--green)'
          : isError
            ? 'var(--red)'
            : 'var(--border)';

        return (
          <div key={agent.name}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 14,
              padding: '12px 0',
            }}>
              {/* Dot */}
              <div style={{ position: 'relative', width: 12, height: 12, flexShrink: 0 }}>
                <div style={{
                  width: 12,
                  height: 12,
                  borderRadius: '50%',
                  background: dotColor,
                  transition: 'background 300ms ease',
                }} />
                {isActive && (
                  <div style={{
                    position: 'absolute',
                    inset: -2,
                    borderRadius: '50%',
                    border: '2px solid var(--green)',
                    animation: 'pulse-ring 1.5s ease-out infinite',
                  }} />
                )}
              </div>

              {/* Name + subtitle */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 14,
                  color: 'var(--text-primary)',
                  fontWeight: isDone || isActive ? 500 : 400,
                  opacity: agent.status === 'waiting' ? 0.5 : 1,
                  transition: 'opacity 300ms ease',
                }}>
                  {agent.name}
                </div>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 12,
                  color: 'var(--text-muted)',
                  marginTop: 2,
                }}>
                  {AGENT_META[agent.name] || ''}
                </div>
              </div>

              {/* Right: checkmark + elapsed */}
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: 'var(--green)',
                opacity: isDone ? 1 : 0,
                transition: 'opacity 300ms ease',
                whiteSpace: 'nowrap',
              }}>
                ✓ {agent.elapsed || ''}
              </div>
            </div>

            {/* Vertical dashed connector */}
            {i < agents.length - 1 && (
              <div style={{
                marginLeft: 5,
                width: 1,
                height: 12,
                borderLeft: '1px dashed var(--border)',
              }} />
            )}
          </div>
        );
      })}
    </div>
  );
}
