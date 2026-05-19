import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from app.schemas.scan import ScanSession

logger = logging.getLogger(__name__)

DB_PATH = Path("data/aria.db")

def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT,
                scan_name TEXT DEFAULT '',
                status TEXT,
                progress REAL,
                message TEXT,
                started_at TEXT,
                finished_at TEXT,
                error TEXT,
                total_tasks INTEGER,
                completed_tasks INTEGER,
                results_json TEXT,
                report_html TEXT,
                report_md TEXT,
                events_json TEXT,
                done INTEGER
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                run_id TEXT PRIMARY KEY,
                scan_id TEXT,
                target TEXT,
                target_name TEXT,
                timestamp TEXT,
                status TEXT,
                config_json TEXT,
                ground_truth_version TEXT,
                results_json TEXT,
                secure_mode_results_json TEXT,
                summary_json TEXT
            )
        ''')
        conn.commit()
        
        # Migration: Add scan_name if it doesn't exist
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN scan_name TEXT DEFAULT ''")
            conn.commit()
            logger.info("Migrated scans table: added scan_name")
        except sqlite3.OperationalError:
            pass # Column already exists
            
    cleanup_interrupted_scans()
    logger.info(f"Database initialized at {DB_PATH}")

def cleanup_interrupted_scans() -> None:
    from datetime import datetime, timezone
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE scans 
                SET status = 'failed', 
                    error = 'Scan interrupted by server restart', 
                    finished_at = ?
                WHERE status IN ('running', 'pending', 'queued')
            """, (datetime.now(timezone.utc).isoformat(),))
            conn.execute("""
                UPDATE benchmark_runs 
                SET status = 'failed'
                WHERE status IN ('running', 'computing')
            """)
            conn.commit()
        logger.info("Interrupted scans and benchmarks marked as failed")
    except Exception as e:
        logger.error(f"Failed to cleanup interrupted scans: {e}")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# --- Scan persistence ---

def save_scan(session: ScanSession) -> None:
    try:
        results_json = json.dumps([r.model_dump() for r in session.results]) if session.results else "[]"
        events_json = json.dumps(session._events) if session._events else "[]"
        
        with get_connection() as conn:
            conn.execute('''
                INSERT INTO scans (
                    scan_id, target_url, scan_name, status, progress, message, started_at, finished_at, 
                    error, total_tasks, completed_tasks, results_json, report_html, report_md, events_json, done
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    target_url=excluded.target_url,
                    scan_name=excluded.scan_name,
                    status=excluded.status,
                    progress=excluded.progress,
                    message=excluded.message,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    error=excluded.error,
                    total_tasks=excluded.total_tasks,
                    completed_tasks=excluded.completed_tasks,
                    results_json=excluded.results_json,
                    report_html=excluded.report_html,
                    report_md=excluded.report_md,
                    events_json=excluded.events_json,
                    done=excluded.done
            ''', (
                session.scan_id, session.target_url, session.scan_name, session.status, session.progress, session.message,
                session.started_at, session.finished_at, session.error, session.total_tasks, session.completed_tasks,
                results_json, session.report_html, session.report_md, events_json, int(session._done)
            ))
    except Exception as e:
        logger.error(f"Failed to save scan {session.scan_id} to DB: {e}")

def _row_to_scan_session(row: sqlite3.Row) -> ScanSession:
    from core.validator.rule_validator import ValidationResult
    
    session = ScanSession(
        scan_id=row["scan_id"],
        target_url=row["target_url"],
        scan_name=row.keys().count("scan_name") > 0 and row["scan_name"] or "",
        status=row["status"],
        progress=row["progress"],
        message=row["message"],
        started_at=row["started_at"] or "",
        finished_at=row["finished_at"] or "",
        error=row["error"] or "",
        total_tasks=row["total_tasks"],
        completed_tasks=row["completed_tasks"]
    )
    session.report_html = row["report_html"] or ""
    session.report_md = row["report_md"] or ""
    session._done = bool(row["done"])
    
    if row["results_json"]:
        try:
            results_data = json.loads(row["results_json"])
            session.results = [ValidationResult(**r) for r in results_data]
        except Exception:
            session.results = []
            
    if row["events_json"]:
        try:
            session._events = json.loads(row["events_json"])
        except Exception:
            session._events = []
            
    return session

def get_scan(scan_id: str) -> ScanSession | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return _row_to_scan_session(row)

def get_all_scans() -> list[ScanSession]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [_row_to_scan_session(row) for row in rows]

# --- Benchmark persistence ---

def save_benchmark_run(run: dict[str, Any]) -> None:
    try:
        config_json = json.dumps(run.get("config", {}))
        results_json = json.dumps(run.get("results", []))
        secure_mode_results_json = json.dumps(run.get("secure_mode_results", []))
        summary_json = json.dumps(run.get("summary", {}))
        
        with get_connection() as conn:
            conn.execute('''
                INSERT INTO benchmark_runs (
                    run_id, scan_id, target, target_name, timestamp, status, 
                    config_json, ground_truth_version, results_json, secure_mode_results_json, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    scan_id=excluded.scan_id,
                    target=excluded.target,
                    target_name=excluded.target_name,
                    timestamp=excluded.timestamp,
                    status=excluded.status,
                    config_json=excluded.config_json,
                    ground_truth_version=excluded.ground_truth_version,
                    results_json=excluded.results_json,
                    secure_mode_results_json=excluded.secure_mode_results_json,
                    summary_json=excluded.summary_json
            ''', (
                run.get("run_id"), run.get("scan_id"), run.get("target"), run.get("target_name"),
                run.get("timestamp"), run.get("status"), config_json, run.get("ground_truth_version"),
                results_json, secure_mode_results_json, summary_json
            ))
    except Exception as e:
        logger.error(f"Failed to save benchmark run to DB: {e}")

def get_all_benchmark_runs() -> list[dict[str, Any]]:
    runs = []
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM benchmark_runs ORDER BY timestamp DESC").fetchall()
        for row in rows:
            runs.append({
                "run_id": row["run_id"],
                "scan_id": row["scan_id"],
                "target": row["target"],
                "target_name": row["target_name"],
                "timestamp": row["timestamp"],
                "status": row["status"],
                "config": json.loads(row["config_json"]) if row["config_json"] else {},
                "ground_truth_version": row["ground_truth_version"],
                "results": json.loads(row["results_json"]) if row["results_json"] else [],
                "secure_mode_results": json.loads(row["secure_mode_results_json"]) if row["secure_mode_results_json"] else [],
                "summary": json.loads(row["summary_json"]) if row["summary_json"] else {}
            })
    return runs

def get_benchmark_run(run_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM benchmark_runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            return None
        return {
            "run_id": row["run_id"],
            "scan_id": row["scan_id"],
            "target": row["target"],
            "target_name": row["target_name"],
            "timestamp": row["timestamp"],
            "status": row["status"],
            "config": json.loads(row["config_json"]) if row["config_json"] else {},
            "ground_truth_version": row["ground_truth_version"],
            "results": json.loads(row["results_json"]) if row["results_json"] else [],
            "secure_mode_results": json.loads(row["secure_mode_results_json"]) if row["secure_mode_results_json"] else [],
            "summary": json.loads(row["summary_json"]) if row["summary_json"] else {}
        }

def delete_benchmark_run(run_id: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM benchmark_runs WHERE run_id = ?", (run_id,))
