import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse

from harness.db import init_db, get_coverage_summary, get_open_findings

init_db()

app = FastAPI(title="AgentForge", description="Adversarial AI Security Platform")

_active_sessions: dict[str, str] = {}  # session_id -> status


@app.get("/", response_class=HTMLResponse)
def dashboard():
    coverage = get_coverage_summary()
    findings = get_open_findings()
    reports = sorted(Path("reports").glob("*.md"))
    active = [sid for sid, status in _active_sessions.items() if status == "running"]

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

    report_links = "".join(
        f"<li><a href='/report/{r.stem}' style='color:#74c0fc'>{r.stem}</a></li>"
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
  </style>
</head>
<body>
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
  <form action='/run' method='post'>
    <button type='submit'>▶ Run Attack Session</button>
  </form>

  <h2>Open Findings ({len(findings)})</h2>
  {"<p style='color:#b0c4de'>No confirmed exploits yet.</p>" if not findings else
   "<ul>" + "".join(f"<li>{f['category']} / {f['subcategory']} — <strong style='color:#ff6b6b'>{f['severity'].upper()}</strong></li>" for f in findings) + "</ul>"}

  <h2>Vulnerability Reports ({len(reports)})</h2>
  {"<p style='color:#b0c4de'>No reports filed yet.</p>" if not reports else f"<ul>{report_links}</ul>"}

  <p style='color:#1a2d4a;margin-top:3rem'>
    AgentForge · Gauntlet AI Week 3 · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
  </p>
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
    <style>body{{background:#0f1b2d;color:#fff;font-family:monospace;padding:2rem;}}
    a{{color:#4a9eff;}}</style></head>
    <body><a href='/'>← back</a><pre style='white-space:pre-wrap'>{path.read_text()}</pre></body></html>"""


@app.get("/health")
def health():
    return {"status": "ok", "service": "agentforge",
            "target": os.environ.get("TARGET_URL"),
            "red_team_provider": os.environ.get("RED_TEAM_PROVIDER", "ollama")}
