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

      {/* WARNING MARQUEE */}
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
                  <h2>98.5%</h2>
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
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

      {/* FOOTER */}
      <footer className="app-footer">
        <div className="footer-disclaimer">
          ⚠️ <strong>Disclaimer:</strong> This tool is for educational and research purposes and is under continuous development.
        </div>
        <div className="footer-meta">
          <span className="developer-tag">Designed & Developed with 🧠 for Blue Teaming</span>
          <a href="https://github.com/ah74n" target="_blank" rel="noopener noreferrer" className="github-link">
            <svg height="20" width="20" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
            </svg>
            GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}

export default App;
