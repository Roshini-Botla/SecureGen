import React from 'react';

export default function ResultsPanel({ result, onReset }) {
  const { filename, language, metrics, vulnerabilities } = result;

  const sevColor = { CRITICAL: '#a32d2d', HIGH: '#993c1d', MEDIUM: '#854f0b', LOW: '#3b6d11', INFO: '#185fa5' };
  const sevBg = { CRITICAL: '#1e0f0f', HIGH: '#1e1209', MEDIUM: '#1e1608', LOW: '#0f1e0f', INFO: '#0f1420' };
  const sevBorder = { CRITICAL: '#a32d2d', HIGH: '#993c1d', MEDIUM: '#854f0b', LOW: '#3b6d11', INFO: '#185fa5' };
  const riskColor = { CRITICAL: '#a32d2d', HIGH: '#993c1d', MEDIUM: '#854f0b', LOW: '#3b6d11', SAFE: '#1d9e75' };

  return (
    <div style={{ maxWidth: 820, margin: '2rem auto', padding: '0 1.5rem' }}>

      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: '#e0e6f0' }}>Analysis Report</h2>
          <span style={{ fontSize: 12, color: '#555' }}>{filename} · {language}</span>
        </div>
        <button onClick={onReset} style={{ fontSize: 12, color: '#888', background: 'transparent', border: '1px solid #2a3045', borderRadius: 6, padding: '6px 14px', cursor: 'pointer' }}>
          ↺ New Scan
        </button>
      </div>

      {/* Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Security Score', value: metrics.security_score + '/100', color: metrics.security_score >= 80 ? '#1d9e75' : metrics.security_score >= 50 ? '#854f0b' : '#a32d2d' },
          { label: 'Risk Level', value: metrics.risk_level, color: riskColor[metrics.risk_level] || '#888' },
          { label: 'Total Issues', value: metrics.vulnerability_count, color: metrics.vulnerability_count === 0 ? '#1d9e75' : '#a32d2d' },
          { label: 'Critical', value: metrics.critical_count, color: metrics.critical_count > 0 ? '#a32d2d' : '#1d9e75' },
          { label: 'High', value: metrics.high_count, color: metrics.high_count > 0 ? '#993c1d' : '#1d9e75' },
          { label: 'Lines Scanned', value: metrics.total_lines, color: '#185fa5' },
        ].map((card, i) => (
          <div key={i} style={{ background: '#0d1117', border: '1px solid #1a1f2e', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: card.color }}>{card.value}</div>
            <div style={{ fontSize: 11, color: '#555', marginTop: 4 }}>{card.label}</div>
          </div>
        ))}
      </div>

      {/* Risk Banner */}
      <div style={{ background: '#0d1117', borderLeft: `3px solid ${riskColor[metrics.risk_level] || '#888'}`, borderRadius: '0 8px 8px 0', padding: '1rem 1.25rem', marginBottom: 24 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: riskColor[metrics.risk_level], marginBottom: 4, letterSpacing: '0.08em' }}>
          OVERALL RISK: {metrics.risk_level}
        </div>
        <div style={{ fontSize: 13, color: '#888', lineHeight: 1.6 }}>
          {metrics.vulnerability_count === 0
            ? 'No vulnerabilities detected. This code passed all security checks.'
            : `Found ${metrics.vulnerability_count} vulnerabilit${metrics.vulnerability_count > 1 ? 'ies' : 'y'} — review and fix the issues below before deploying.`}
        </div>
      </div>

      {/* Vulnerabilities */}
      {vulnerabilities.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '3rem', border: '1px solid #1a1f2e', borderRadius: 10, background: '#0d1117' }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>✅</div>
          <p style={{ fontSize: 16, fontWeight: 600, color: '#e0e6f0' }}>No vulnerabilities detected</p>
          <span style={{ fontSize: 13, color: '#555' }}>This code passed all security checks.</span>
        </div>
      ) : (
        <>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#555', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
            Vulnerabilities Detected ({vulnerabilities.length})
          </div>
          {vulnerabilities.map((v, i) => (
            <div key={i} style={{ background: '#0d1117', border: `1px solid ${sevBorder[v.severity] || '#2a3045'}`, borderRadius: 10, padding: '1rem 1.25rem', marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div style={{ fontSize: 15, fontWeight: 600, color: '#e0e6f0' }}>{v.id} · {v.title}</div>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 4, background: sevBg[v.severity], color: sevColor[v.severity], border: `1px solid ${sevBorder[v.severity]}`, whiteSpace: 'nowrap' }}>
                  {v.severity}
                </span>
              </div>
              <div style={{ fontSize: 13, color: '#888', lineHeight: 1.6, marginBottom: 10 }}>{v.description}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                <span style={{ fontSize: 11, padding: '2px 8px', border: '1px solid #2a3045', borderRadius: 4, color: '#555' }}>{v.cwe_id}</span>
                {v.line_number && <span style={{ fontSize: 11, padding: '2px 8px', border: '1px solid #2a3045', borderRadius: 4, color: '#555' }}>Line {v.line_number}</span>}
                {v.cvss_score && <span style={{ fontSize: 11, padding: '2px 8px', border: '1px solid #2a3045', borderRadius: 4, color: '#555' }}>CVSS {v.cvss_score}</span>}
              </div>
              {v.recommendation && (
                <div style={{ background: '#0a1a12', border: '1px solid #1d9e75', borderRadius: 6, padding: '0.75rem 1rem' }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: '#1d9e75', marginBottom: 4 }}>💡 RECOMMENDED FIX</div>
                  <div style={{ fontSize: 13, color: '#888', lineHeight: 1.5 }}>{v.recommendation}</div>
                </div>
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
}