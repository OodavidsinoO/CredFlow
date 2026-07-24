"""SQLite persistence layer for CredFlow scan progress."""

import contextlib
import sqlite3
import threading
from datetime import UTC, datetime

from credflow.models import Target


class StateManager:
    """Manages scan job state in a SQLite database with thread-safe writes."""

    def __init__(self, db_path: str, max_retries: int = 1):
        self._db_path = db_path
        self._max_retries = max_retries
        self._lock = threading.Lock()
        self.init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Create a new connection (thread-safe for reads)."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def init_db(self) -> None:
        """Create the targets table if it doesn't exist, and migrate if needed."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    ip TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    os_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    scan_id INTEGER,
                    error TEXT,
                    retries INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    completed_at TEXT,
                    report_nessus TEXT,
                    report_db TEXT
                )
            """)
            # Migrations: add columns that may be missing from older schemas
            for col, col_type in [
                ("scan_id", "INTEGER"),
                ("error", "TEXT"),
                ("retries", "INTEGER NOT NULL DEFAULT 0"),
                ("started_at", "TEXT"),
                ("completed_at", "TEXT"),
                ("report_nessus", "TEXT"),
                ("report_db", "TEXT"),
                ("escalation_method", "TEXT"),
                ("escalation_user", "TEXT"),
                ("escalation_password", "TEXT"),
            ]:
                with contextlib.suppress(sqlite3.OperationalError):
                    conn.execute(f"ALTER TABLE targets ADD COLUMN {col} {col_type}")
            conn.commit()
            conn.close()

    def load_targets(self, targets: list[Target]) -> int:
        """Insert targets into DB. Returns count of newly inserted (pending) rows.
        Already-completed targets are left untouched (INSERT OR IGNORE).
        """
        inserted = 0
        with self._lock:
            conn = self._get_conn()
            for t in targets:
                try:
                    conn.execute(
                        """INSERT INTO targets (ip, username, password, os_type,
                           escalation_method, escalation_user, escalation_password)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (t.ip, t.username, t.password, t.os_type,
                         t.escalation_method, t.escalation_user, t.escalation_password),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    # Already exists — skip
                    pass
            conn.commit()
            conn.close()
        return inserted

    def claim_next(self) -> Target | None:
        """Atomically claim the next pending target. Returns None if no pending work."""
        with self._lock:
            conn = self._get_conn()
            conn.execute("BEGIN EXCLUSIVE")
            row = conn.execute(
                "SELECT * FROM targets WHERE status = 'pending' ORDER BY ip LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                conn.close()
                return None
            now = datetime.now(UTC).isoformat()
            conn.execute(
                "UPDATE targets SET status = 'running', started_at = ? WHERE ip = ?",
                (now, row["ip"]),
            )
            conn.execute("COMMIT")
            conn.close()
            return Target(
                ip=row["ip"],
                username=row["username"],
                password=row["password"],
                os_type=row["os_type"],
                escalation_method=row["escalation_method"] if "escalation_method" in row else None,  # noqa: SIM401
                escalation_user=row["escalation_user"] if "escalation_user" in row else None,  # noqa: SIM401
                escalation_password=row["escalation_password"] if "escalation_password" in row else None,  # noqa: SIM401
            )

    def mark_completed(
        self, ip: str, report_nessus: str, report_db: str
    ) -> None:
        """Mark a target as completed with report paths."""
        now = datetime.now(UTC).isoformat()
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """UPDATE targets SET status = 'completed',
                   completed_at = ?, report_nessus = ?, report_db = ?
                   WHERE ip = ?""",
                (now, report_nessus, report_db, ip),
            )
            conn.commit()
            conn.close()

    def mark_failed(self, ip: str, error: str) -> bool:
        """Mark a target as failed. Returns True if it will be retried (reset to pending)."""
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """UPDATE targets SET status = 'failed', error = ?,
                   retries = retries + 1, completed_at = ?
                   WHERE ip = ?""",
                (error, datetime.now(UTC).isoformat(), ip),
            )
            row = conn.execute(
                "SELECT retries FROM targets WHERE ip = ?", (ip,)
            ).fetchone()
            will_retry = False
            if row and row["retries"] <= self._max_retries:
                conn.execute(
                    "UPDATE targets SET status = 'pending', error = NULL WHERE ip = ?",
                    (ip,),
                )
                will_retry = True
            conn.commit()
            conn.close()
        return will_retry

    def get_progress(self) -> dict[str, int]:
        """Return counts grouped by status."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM targets GROUP BY status"
        ).fetchall()
        conn.close()
        return {row["status"]: row["cnt"] for row in rows}

    def get_failures(self) -> list[dict]:
        """Return all rows with status='failed'."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT ip, error, retries FROM targets WHERE status = 'failed'"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_completed_reports(self) -> list[dict]:
        """Return all completed target report paths."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT ip, report_nessus, report_db FROM targets WHERE status = 'completed'"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def reset_failed(self) -> int:
        """Reset all failed targets back to pending. Returns count reset."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute(
                "UPDATE targets SET status = 'pending', error = NULL "
                "WHERE status = 'failed'"
            )
            count = cur.rowcount
            conn.commit()
            conn.close()
        return count

    def reset_all(self) -> None:
        """Drop and recreate the targets table (fresh start)."""
        conn = sqlite3.connect(self._db_path)
        conn.execute("DROP TABLE IF EXISTS targets")
        conn.commit()
        conn.close()
        self.init_db()

    def reset_running(self) -> int:
        """Reset all running targets back to pending (e.g. after a killed process).
        Returns count reset."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute(
                "UPDATE targets SET status = 'pending', retries = 0 "
                "WHERE status = 'running'"
            )
            count = cur.rowcount
            conn.commit()
            conn.close()
        return count

    def is_empty(self) -> bool:
        """Check if the targets table has any rows."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM targets").fetchone()
        conn.close()
        return row["cnt"] == 0
