import React, { useState } from 'react';
import UploadPanel from './components/UploadPanel';
import ResultsPanel from './components/ResultsPanel';
import Header from './components/Header';
import './App.css';

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async (file) => {
    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/analyze', {
        method: 'POST',
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || 'Analysis failed. Please try again.');
      } else {
        setResult(data);
      }
    } catch (err) {
      setError('Could not connect to the backend. Make sure the server is running on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setError(null);
  };

  return (
    <div className="app">
      <Header />
      <main className="main">
        {!result ? (
          <UploadPanel onAnalyze={handleAnalyze} loading={loading} error={error} />
        ) : (
          <ResultsPanel result={result} onReset={handleReset} />
        )}
      </main>
      <footer className="footer">
        <span>SecureGen v1.0</span>
        <span className="sep">·</span>
        <span>Based on research: <em>Security Vulnerabilities in AI-Generated Code</em> (Schreiber & Tippe, 2025)</span>
      </footer>
    </div>
  );
}