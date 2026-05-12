import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

_data_dir = Path(__file__).parent.parent / "data"
_data_dir.mkdir(exist_ok=True)
DB_PATH = _data_dir / "agentforge.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS exploits (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                subcategory TEXT,
                severity TEXT NOT NULL,
                verdict TEXT NOT NULL,
                attack_payload TEXT NOT NULL,
                attack_response TEXT,
                rationale TEXT,
                regression_candidate INTEGER DEFAULT 0,
                report_path TEXT,
                target_version TEXT,
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );

            CREATE TABLE IF NOT EXISTS regression_runs (
                id TEXT PRIMARY KEY,
                exploit_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                run_at TEXT NOT NULL,
                FOREIGN KEY (exploit_id) REFERENCES exploits(id)
            );

            CREATE TABLE IF NOT EXISTS coverage (
                category TEXT PRIMARY KEY,
                total_cases INTEGER DEFAULT 0,
                successes INTEGER DEFAULT 0,
                failures INTEGER DEFAULT 0,
                partials INTEGER DEFAULT 0,
                last_run_at TEXT
            );
        """)


def insert_exploit(
    category: str,
    subcategory: str,
    severity: str,
    verdict: str,
    attack_payload: dict,
    attack_response: dict | None,
    rationale: str,
    regression_candidate: bool,
    report_path: str | None = None,
    target_version: str = "live",
) -> str:
    exploit_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO exploits (id, category, subcategory, severity, verdict,
                attack_payload, attack_response, rationale, regression_candidate,
                report_path, target_version, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                exploit_id, category, subcategory, severity, verdict,
                json.dumps(attack_payload),
                json.dumps(attack_response) if attack_response else None,
                rationale, int(regression_candidate),
                report_path, target_version, now,
            ),
        )
        conn.execute(
            """
            INSERT INTO coverage (category, total_cases, successes, failures, partials, last_run_at)
            VALUES (?, 1, ?, ?, ?, ?)
            ON CONFLICT(category) DO UPDATE SET
                total_cases = total_cases + 1,
                successes   = successes + excluded.successes,
                failures    = failures  + excluded.failures,
                partials    = partials  + excluded.partials,
                last_run_at = excluded.last_run_at
            """,
            (
                category,
                1 if verdict == "success" else 0,
                1 if verdict == "failure" else 0,
                1 if verdict == "partial" else 0,
                now,
            ),
        )
    return exploit_id


def get_coverage_summary() -> dict:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM coverage").fetchall()
        return {row["category"]: dict(row) for row in rows}


def get_regression_candidates() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM exploits WHERE regression_candidate = 1 ORDER BY severity DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def record_regression_run(exploit_id: str, verdict: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO regression_runs (id, exploit_id, verdict, run_at) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), exploit_id, verdict, datetime.now(timezone.utc).isoformat()),
        )


def get_recent_verdicts(limit: int = 20) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT id, category, subcategory, severity, verdict, rationale,
                      regression_candidate, created_at
               FROM exploits
               ORDER BY created_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_open_findings() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM exploits WHERE resolved_at IS NULL ORDER BY severity DESC"
        ).fetchall()
        return [dict(row) for row in rows]
