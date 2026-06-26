import React, { useState } from 'react';

export default function UploadPanel({ onAnalyze, loading, error }) {
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  };

  return (
    <div style={{ maxWidth: 640, margin: '3rem auto', padding: '0 1.5rem' }}>
      <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: 28, fontWeight: 700, color: '#e0e6f0', marginBottom: 8 }}>Scan Your Code</h2>
        <p style={{ fontSize: 14, color: '#888' }}>Upload AI-generated code to detect vulnerabilities, CWEs, and security risks</p>
      </div>

      <div
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => document.getElementById('file-input').click()}
        style={{
          border: `2px dashed ${dragging ? '#1d9e75' : '#2a3045'}`,
          borderRadius: 12,
          padding: '3rem 2rem',
          textAlign: 'center',
          cursor: 'pointer',
          background: dragging ? '#0f1e1a' : '#0d1117',
          transition: 'all 0.15s',
          marginBottom: 16
        }}
      >
        <div style={{ fontSize: 48, marginBottom: 16 }}>📂</div>
        <p style={{ fontSize: 16, color: '#aaa', marginBottom: 8 }}>Drop a file or click to upload</p>
        <span style={{ fontSize: 12, color: '#555' }}>.py · .js · .java · .cpp · .ts · .go · .php · and more</span>
      </div>
      <input id="file-input" type="file" style={{ display: 'none' }} onChange={e => setFile(e.target.files[0])} />

      {file && (
        <div style={{ background: '#0f2318', border: '1px solid #1d9e75', borderRadius: 8, padding: '0.75rem 1rem', marginBottom: 16, fontSize: 13, color: '#1d9e75', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>✓</span> <strong>{file.name}</strong> <span style={{ color: '#555', marginLeft: 'auto' }}>{(file.size / 1024).toFixed(1)} KB</span>
        </div>
      )}

      {error && (
        <div style={{ background: '#1e0f0f', border: '1px solid #a32d2d', borderRadius: 8, padding: '0.75rem 1rem', marginBottom: 16, fontSize: 13, color: '#f09595' }}>
          ⚠ {error}
        </div>
      )}

      <button
        onClick={() => file && onAnalyze(file)}
        disabled={loading || !file}
        style={{
          width: '100%', padding: '14px', fontSize: 15, fontWeight: 600,
          border: 'none', borderRadius: 8,
          background: loading || !file ? '#1a1f2e' : 'linear-gradient(135deg, #1d9e75, #0f6e56)',
          color: loading || !file ? '#555' : '#fff',
          cursor: loading || !file ? 'not-allowed' : 'pointer',
          transition: 'all 0.15s'
        }}
      >
        {loading ? '⏳ Analyzing...' : '🔍 Analyze for Vulnerabilities'}
      </button>

      <div style={{ display: 'flex', justifyContent: 'center', gap: 24, marginTop: 32 }}>
        {['CWE Detection', 'OWASP Mapping', 'Fix Suggestions', 'Severity Scoring'].map(f => (
          <div key={f} style={{ textAlign: 'center' }}>
            <div style={{ width: 8, height: 8, background: '#1d9e75', borderRadius: '50%', margin: '0 auto 6px' }}></div>
            <span style={{ fontSize: 11, color: '#555' }}>{f}</span>
          </div>
        ))}
      </div>
    </div>
  );
}