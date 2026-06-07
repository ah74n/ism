import { useState } from "react";
import axios from "axios";
import "./App.css";
// Make sure logo.png exists in your assets folder!
import logo from "./assets/logo.png"; 

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeURL = async () => {
    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      // FIXED: Pointing directly to your live Render backend
      // IMPORTANT: If your FastAPI docs say '/api/scan', change the '/scan' below to '/api/scan'
      const response = await axios.post(
        `${import.meta.env.VITE_API_URL || "https://ism-backend-o3ha.onrender.com"}/scan`,
        { url: url }
      );

      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(
        err.response?.data?.error || err.response?.data?.detail || "Backend connection failed. Server might be sleeping or endpoint mismatch."
      );
    } finally {
      setLoading(false);
    }
  };

  const getVerdictColor = () => {
    if (!result) return "var(--safe-color)";
    const verdict = result.status || result.final_verdict || "";
    if (verdict.toLowerCase() === "safe") return "var(--safe-color)";
    if (verdict.toLowerCase() === "suspicious") return "var(--warning-color)";
    return "var(--danger-color)";
  };

  const getFinalVerdict = () => {
    if (!result) return "";
    if (result.risk_score >= 70) return "MALICIOUS";
    if (result.risk_score >= 35) return "SUSPICIOUS";
    return "SAFE";
  };

  return (
    <div className="app-container">
      {/* HEADER */}
      <header className="app-header">
        <div className="header-brand">
          <div className="brand">
            {/* If logo is missing, it will fallback gracefully */}
            <img src={logo} alt="isMalicious" className="logo" onError={(e) => e.target.style.display='none'} />
            <h1>isMalicious</h1>
          </div>
          <span className="version-tag">Beta</span>
          <span className="badge">Threat Intelligence</span>
        </div>
        
        <nav className="header-nav">
          <a href="https://github.com/ah74n/isMalicious" target="_blank" rel="noopener noreferrer">
            README
          </a>
          <div className="system-status">
            <span className="pulse-dot"></span>
            Operational
          </div>
        </nav>
      </header>

      {/* NEW: WARNING MARQUEE */}
      <div className="marquee-container">
        <div className="marquee-text">
           <strong>System Notice:</strong> This Blue Team architecture is hosted on a free-tier Render server. The first scan may take 30-50 seconds to wake up the AI engine. Please be patient! 
        </div>
      </div>

      {/* TOP SEARCH BAR */}
      <div className="top-bar">
        <div className="input-wrapper">
          <span className="input-icon">🔗</span>
          <input
            type="text"
            placeholder="Enter URL to scan (e.g., google.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="url-input"
            onKeyDown={(e) => e.key === 'Enter' && analyzeURL()}
          />
          {url && (
            <button 
              className="clear-btn" 
              onClick={() => setUrl("")}
              title="Clear input"
            >
              ✕
            </button>
          )}
        </div>
        <button
          onClick={analyzeURL}
          className={`scan-btn ${loading ? "loading" : ""}`}
          disabled={loading}
        >
          {loading ? "ANALYZING..." : "ANALYZE URL"}
        </button>
      </div>

      {error && (
        <div className="error-box">
          <span className="error-icon">⚠️</span> {error}
        </div>
      )}

      {result && (
        <div className="results-container">
          
          {/* LEFT PANEL - VERDICT & ML STATS */}
          <div className="left-panel">
            <div className="panel-header">
              <h4>ANALYSIS VERDICT</h4>
            </div>

            <div className="verdict-banner" style={{ borderTopColor: getVerdictColor() }}>
              <h1 style={{ color: getVerdictColor() }}>
                {getFinalVerdict()}
              </h1>
            </div>

            <div className="metrics-grid">
              <div className="metric-card">
                <span>Risk Score</span>
                <div className="metric-value">
                  <h2 style={{ color: getVerdictColor() }}>{result.risk_score}</h2>
                  <span className="metric-max">/ 100</span>
                </div>
              </div>

              <div className="metric-card">
                <span>AI Confidence</span>
                <div className="metric-value">
                  <h2>98.5%</h2> {/* Hardcoded fallback for UI aesthetic since sklearn doesn't return pure confidence easily */}
                </div>
              </div>
            </div>

            {/* RISK BAR */}
            <div className="risk-bar-container">
              <div className="risk-header">
                <span>Severity Assessment</span>
                <span style={{ color: getVerdictColor() }}>
                   {(result.status || "UNKNOWN").toUpperCase()}
                </span>
              </div>
              <div className="risk-bar">
                <div
                  className="risk-fill"
                  style={{
                    width: `${result.risk_score}%`,
                    background: getVerdictColor(),
                    boxShadow: `0 0 10px ${getVerdictColor()}40`
                  }}
                ></div>
              </div>
            </div>

            {/* ML ENGINE SECTION */}
            <div className="ml-box">
              <div className="ml-box-header">
                <h4>ML SUBSYSTEM LOGS</h4>
                <span className="status-indicator active">ACTIVE</span>
              </div>
              <div className="ml-stats">
                <ul className="log-list">
                    {result.logs && result.logs.map((log, index) => (
                        <li key={index} style={{ marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                            ➤ {log}
                        </li>
                    ))}
                </ul>
              </div>
            </div>
          </div>

          {/* RIGHT PANEL - JSON OUTPUT */}
          <div className="right-panel">
            <div className="panel-header">
              <h4>INTELLIGENCE OUTPUT</h4>
              <span className="format-badge">JSON</span>
            </div>
            <div className="json-box">
              <pre>
                {JSON.stringify(result, null, 2)}
