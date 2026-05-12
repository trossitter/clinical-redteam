import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse

from harness.db import init_db, get_coverage_summary, get_open_findings, get_recent_verdicts

init_db()

app = FastAPI(title="AgentForge", description="Adversarial AI Security Platform")

_active_sessions: dict[str, str] = {}  # session_id -> status


_VERDICT_COLORS = {
    "success":   ("#ff6b6b", "#2a1a1a"),
    "partial":   ("#ffd43b", "#2a2200"),
    "failure":   ("#4a9eff", "#0f1b2d"),
    "uncertain": ("#cc5de8", "#1e0f2a"),
}

def _render_verdict_feed(verdicts: list[dict]) -> str:
    cards = ""
    for v in verdicts:
        color, bg = _VERDICT_COLORS.get(v["verdict"], ("#b0c4de", "#1a2d4a"))
        ts = v["created_at"][:19].replace("T", " ") + " UTC" if v.get("created_at") else ""
        reg = "<span style='color:#51cf66;font-size:0.8rem'>✓ regression candidate</span>" if v.get("regression_candidate") else ""
        _acronyms = {"soap": "SOAP", "phi": "PHI", "pid": "PID", "ehr": "EHR", "dob": "DOB"}
        raw = v["subcategory"].replace("_", " ")
        keyword = " ".join(_acronyms.get(w.lower(), w.capitalize()) for w in raw.split())
        rationale = v.get("rationale", "")
        # First sentence as muted preview
        first_sentence = rationale.split(". ")[0].strip()
        if len(first_sentence) > 130:
            first_sentence = first_sentence[:127] + "…"
        cards += f"""
        <div style='background:{bg};border-left:4px solid {color};padding:0.9rem 1.2rem;
                    margin-bottom:0.7rem;border-radius:0 4px 4px 0;'>
          <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:0.55rem'>
            <div>
              <span style='color:{color};font-size:1.05rem;font-weight:900;letter-spacing:0.08em'>
                {v["verdict"].upper()}
              </span>
              <span style='color:#4a6080;font-size:0.8rem;margin-left:0.8rem'>
                {v["category"]}
              </span>
            </div>
            <div style='text-align:right;font-size:0.78rem;color:#4a6080'>
              {v["severity"].upper()} &nbsp;·&nbsp; {ts}<br>{reg}
            </div>
          </div>
          <details>
            <summary style='cursor:pointer;list-style:none;outline:none;'>
              <span style='color:{color};font-weight:700;font-size:0.9rem'>{keyword}</span>
              <span style='color:#6a8090;font-size:0.85rem;margin-left:0.6rem'>— {first_sentence}.</span>
            </summary>
            <div style='color:#c8d8e8;font-size:0.88rem;line-height:1.6;
                        border-top:1px solid rgba(255,255,255,0.06);
                        margin-top:0.6rem;padding-top:0.6rem'>
              {rationale}
            </div>
          </details>
        </div>"""
    return cards


@app.get("/", response_class=HTMLResponse)
def dashboard():
    coverage = get_coverage_summary()
    findings = get_open_findings()
    reports = sorted(Path("reports").glob("*.md"))
    active = [sid for sid, status in _active_sessions.items() if status == "running"]
    verdicts = get_recent_verdicts(20)

    rows = ""
    for cat, data in coverage.items():
        rows += f"""
        <tr>
          <td>{cat}</td>
          <td>{data['total_cases']}</td>
          <td style='color:#51cf66'>{data['successes']}</td>
          <td style='color:#ffd43b'>{data['partials']}</td>
          <td style='color:#ff6b6b'>{data['failures']}</td>
          <td>{data.get('last_run_at','—')[:19] if data.get('last_run_at') else '—'}</td>
        </tr>"""

    base = "/agentforge"
    report_links = "".join(
        f"<li><a href='{base}/report/{r.stem}' style='color:#74c0fc'>{r.stem}</a></li>"
        for r in reports
    )

    return f"""<!DOCTYPE html>
<html>
<head>
  <title>AgentForge</title>
  <style>
    body {{ background:#0f1b2d; color:#fff; font-family:monospace; padding:2rem; }}
    h1 {{ color:#4a9eff; }} h2 {{ color:#b0c4de; border-bottom:1px solid #1a2d4a; padding-bottom:0.5rem; }}
    table {{ border-collapse:collapse; width:100%; margin:1rem 0; }}
    th {{ background:#1a3a5c; color:#4a9eff; padding:0.5rem 1rem; text-align:left; }}
    td {{ padding:0.4rem 1rem; border-bottom:1px solid #1a2d4a; }}
    .badge {{ padding:0.2rem 0.6rem; border-radius:4px; font-size:0.85rem; }}
    .online {{ background:#1a4a2a; color:#51cf66; }}
    .running {{ background:#4a3a1a; color:#ffd43b; }}
    button {{ background:#4a9eff; color:#0f1b2d; border:none; padding:0.6rem 1.4rem;
              font-family:monospace; font-size:1rem; cursor:pointer; border-radius:4px; }}
    button:hover {{ background:#74c0fc; }}
    ul {{ color:#b0c4de; }} a {{ color:#74c0fc; }}

    /* ── Gate animation overlay ── */
    #gate-overlay {{
      position: fixed;
      inset: 0;
      z-index: 9999;
      display: flex;
      pointer-events: all;
      overflow: hidden;
    }}

    /* Centre seam — pressurised crack, cold and narrow */
    #gate-overlay::after {{
      content: '';
      position: absolute;
      top: 0; bottom: 0;
      left: 50%;
      width: 0;
      transform: translateX(-50%);
      background: linear-gradient(180deg,
        transparent 0%,
        rgba(220,240,255,0.95) 20%,
        rgba(255,255,255,1)    50%,
        rgba(220,240,255,0.95) 80%,
        transparent 100%);
      opacity: 0;
      z-index: 10001;
      animation: seamGlow 2.6s ease-in-out forwards;
      animation-delay: 0.5s;
    }}

    @keyframes seamGlow {{
      0%   {{ width:0;   opacity:0; }}
      12%  {{ width:3px; opacity:1; }}
      30%  {{ width:4px; opacity:0.7; }}
      48%  {{ width:2px; opacity:0.15; }}
      60%  {{ width:0;   opacity:0; }}
      100% {{ width:0;   opacity:0; }}
    }}


    /* AGENTFORGE title on overlay */
    #gate-title {{
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      z-index: 10002;
      font-family: monospace;
      font-size: clamp(2rem, 6vw, 5rem);
      font-weight: 900;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: #c8d8e8;
      text-shadow:
        0 0 12px #4a9eff,
        0 0 30px #2266cc,
        0 0 60px #1a44aa;
      opacity: 0;
      white-space: nowrap;
      animation: titleReveal 2.6s ease-in-out forwards;
      animation-delay: 0.5s;
      pointer-events: none;
    }}

    @keyframes titleReveal {{
      0%   {{ opacity:0; letter-spacing:0.05em; }}
      20%  {{ opacity:1; letter-spacing:0.18em; }}
      65%  {{ opacity:1; letter-spacing:0.18em; }}
      100% {{ opacity:0; letter-spacing:0.35em; }}
    }}

    /* ── Panel shared styles ── */
    .gate-panel {{
      position: relative;
      width: 50%;
      height: 100%;
      flex-shrink: 0;
      overflow: hidden;
      /* Dark steel gradient */
      background:
        repeating-linear-gradient(
          180deg,
          rgba(255,255,255,0.03) 0px, rgba(255,255,255,0.03) 1px,
          transparent 1px, transparent 12px
        ),
        linear-gradient(
          160deg,
          #1c2530 0%, #0e1520 20%, #1a2535 40%,
          #0b1018 60%, #1e2d40 80%, #0d1520 100%
        );
      box-shadow: inset 0 0 80px rgba(0,0,0,0.8);
      animation-timing-function: cubic-bezier(0.42, 0, 1, 1);
      animation-fill-mode: forwards;
      animation-duration: 1.1s;
      animation-delay: 1.3s;
    }}

    /* Vertical bars (portcullis) */
    .gate-panel::before {{
      content: '';
      position: absolute;
      inset: 0;
      background: repeating-linear-gradient(
        90deg,
        rgba(30,45,65,0.0)  0px,
        rgba(30,45,65,0.0)  22px,
        rgba(8,14,22,0.85)  22px,
        rgba(8,14,22,0.85)  28px,
        rgba(30,45,65,0.0)  28px,
        rgba(30,45,65,0.0)  50px
      );
      z-index: 1;
    }}

    /* Horizontal rail lines */
    .gate-panel::after {{
      content: '';
      position: absolute;
      inset: 0;
      background: repeating-linear-gradient(
        180deg,
        transparent        0px,
        transparent        58px,
        rgba(0,0,0,0.55)   58px,
        rgba(0,0,0,0.55)   66px,
        transparent        66px,
        transparent        120px
      );
      z-index: 2;
    }}

    /* Rivet dots on left panel */
    .gate-left .rivets {{
      position: absolute;
      inset: 0;
      z-index: 3;
      background:
        radial-gradient(circle 4px at 20px 40px,  #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 120px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 200px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 280px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 360px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 440px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 520px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 600px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 680px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 760px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 840px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at 20px 920px, #2a3d52 60%, transparent 61%);
    }}

    /* Rivet dots on right panel */
    .gate-right .rivets {{
      position: absolute;
      inset: 0;
      z-index: 3;
      background:
        radial-gradient(circle 4px at calc(100% - 20px) 40px,  #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 120px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 200px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 280px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 360px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 440px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 520px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 600px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 680px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 760px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 840px, #2a3d52 60%, transparent 61%),
        radial-gradient(circle 4px at calc(100% - 20px) 920px, #2a3d52 60%, transparent 61%);
    }}

    /* Edge highlight — inner seam edge glow */
    .gate-left  {{ box-shadow: inset -4px 0 20px rgba(0,0,0,0.9), inset 0 0 60px rgba(0,0,0,0.6); }}
    .gate-right {{ box-shadow: inset  4px 0 20px rgba(0,0,0,0.9), inset 0 0 60px rgba(0,0,0,0.6); }}

    @keyframes slideLeft {{
      from {{ transform: translateX(0); }}
      to   {{ transform: translateX(-105%); }}
    }}

    @keyframes slideRight {{
      from {{ transform: translateX(0); }}
      to   {{ transform: translateX(105%); }}
    }}

    .gate-left  {{ animation-name: slideLeft;  }}
    .gate-right {{ animation-name: slideRight; }}

    /* Final fade-out of the whole overlay */
    #gate-overlay {{
      animation: overlayFade 0.35s ease-out forwards;
      animation-delay: 2.4s;
    }}

    @keyframes overlayFade {{
      from {{ opacity:1; pointer-events:all; }}
      to   {{ opacity:0; pointer-events:none; }}
    }}
  </style>
</head>
<body>

  <!-- ── Gate animation overlay ── -->
  <div id="gate-overlay">
    <div class="gate-panel gate-left">
      <div class="rivets"></div>
    </div>
    <div id="gate-title">AGENTFORGE</div>
    <div class="gate-panel gate-right">
      <div class="rivets"></div>
    </div>
  </div>
  <!-- ── End gate overlay ── -->

  <h1>AgentForge</h1>
  <p>Adversarial AI Security Platform &nbsp;·&nbsp;
     Target: <a href='https://clinicalcopilot.org'>clinicalcopilot.org</a> &nbsp;·&nbsp;
     <span class='badge online'>● online</span>
     {"&nbsp;<span class='badge running'>⟳ " + str(len(active)) + " session(s) running</span>" if active else ""}
  </p>

  <h2>Coverage</h2>
  <table>
    <tr><th>Category</th><th>Cases</th><th>Success</th><th>Partial</th><th>Failure</th><th>Last Run</th></tr>
    {rows if rows else '<tr><td colspan=6 style="color:#b0c4de">No runs yet — trigger a session below.</td></tr>'}
  </table>

  <h2>Trigger Attack Session</h2>
  <p style='color:#b0c4de'>Starts a full Orchestrator → Red Team → Judge cycle against the live target.</p>
  <button id='run-btn' onclick='triggerRun()'>▶ Run Attack Session</button>
  <span id='run-status' style='margin-left:1rem;color:#51cf66;font-size:0.9rem'></span>

  <h2>Judge Verdicts — Live Feed</h2>
  {"<p style='color:#b0c4de'>No verdicts yet — trigger a session to begin.</p>" if not verdicts else _render_verdict_feed(verdicts)}

  <h2>Open Findings ({len(findings)})</h2>
  {"<p style='color:#b0c4de'>No confirmed exploits yet.</p>" if not findings else
   "<ul>" + "".join(f"<li>{f['category']} / {f['subcategory']} — <strong style='color:#ff6b6b'>{f['severity'].upper()}</strong></li>" for f in findings) + "</ul>"}

  <h2>Vulnerability Reports ({len(reports)})</h2>
  {"<p style='color:#b0c4de'>No reports filed yet.</p>" if not reports else f"<ul>{report_links}</ul>"}

  <p style='color:#1a2d4a;margin-top:3rem'>
    AgentForge · Gauntlet AI Week 3 · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
  </p>

  <script>
    (function() {{
      var overlay = document.getElementById('gate-overlay');
      if (!overlay) return;
      // Skip animation if this load was triggered by auto-refresh
      if (sessionStorage.getItem('autoRefresh')) {{
        sessionStorage.removeItem('autoRefresh');
        overlay.style.display = 'none';
        return;
      }}
      setTimeout(function() {{ overlay.style.display = 'none'; }}, 2850);
    }})();

    function triggerRun() {{
      var btn = document.getElementById('run-btn');
      var status = document.getElementById('run-status');
      btn.disabled = true;
      btn.textContent = '⟳ Starting...';
      var runUrl = window.location.pathname.replace(/\/+$/, '') + '/run';
      fetch(runUrl, {{method:'POST'}})
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          status.textContent = '✓ Session ' + d.session_id.slice(0,8) + ' started';
          btn.textContent = '▶ Run Attack Session';
          btn.disabled = false;
        }})
        .catch(function() {{
          status.style.color = '#ff6b6b';
          status.textContent = '✗ Failed to start session';
          btn.textContent = '▶ Run Attack Session';
          btn.disabled = false;
        }});
    }}

    // Auto-refresh every 20s — flag it so animation is skipped on the reload
    setTimeout(function() {{
      setInterval(function() {{
        sessionStorage.setItem('autoRefresh', '1');
        location.reload();
      }}, 20000);
    }}, 5000);
  </script>
</body>
</html>"""


@app.post("/run")
def trigger_run(background_tasks: BackgroundTasks):
    session_id = str(uuid.uuid4())
    _active_sessions[session_id] = "running"
    background_tasks.add_task(_run_session_task, session_id)
    return {"session_id": session_id, "status": "started",
            "message": "Session running in background. Refresh / to see results."}


def _run_session_task(session_id: str) -> None:
    try:
        from main import run_session
        run_session(session_id)
        _active_sessions[session_id] = "complete"
    except Exception as e:
        _active_sessions[session_id] = f"error: {e}"


@app.get("/findings")
def findings():
    return {"findings": get_open_findings()}


@app.get("/coverage")
def coverage():
    return get_coverage_summary()


@app.get("/report/{report_id}", response_class=HTMLResponse)
def get_report(report_id: str):
    path = Path("reports") / f"{report_id}.md"
    if not path.exists():
        return HTMLResponse("<h1>Not found</h1>", status_code=404)
    content = path.read_text().replace("\n", "<br>").replace("##", "<h2>").replace("#", "<h1>")
    return f"""<!DOCTYPE html><html><head><title>{report_id}</title>
    <style>body{{background:#0f1b2d;color:#fff;font-family:monospace;padding:2rem;line-height:1.6}}
    a{{color:#4a9eff;}}</style></head>
    <body><a href='/agentforge'>← back to dashboard</a><br><br><pre style='white-space:pre-wrap'>{path.read_text()}</pre></body></html>"""


@app.get("/health")
def health():
    return {"status": "ok", "service": "agentforge",
            "target": os.environ.get("TARGET_URL"),
            "red_team_provider": os.environ.get("RED_TEAM_PROVIDER", "ollama")}
