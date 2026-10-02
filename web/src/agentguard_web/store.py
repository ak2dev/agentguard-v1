"""Report storage, keyed by report_cache_key (immutable ref + rule pack + engine).

Only the redacted findings JSON is stored, never the fetched archive, plus any
maintainer response (plain text read from the project's own repository).
``sqlite:///path`` suits a single node; ``postgresql://...`` is for production.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from typing import Protocol

from .models import MaintainerResponse, StoredReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
  key TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  locator TEXT NOT NULL,
  resolved TEXT NOT NULL,
  rule_pack_version TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  scanned_at TEXT NOT NULL,
  report_json TEXT NOT NULL
)"""
_INDEX = "CREATE INDEX IF NOT EXISTS reports_source ON reports (kind, locator, scanned_at)"
_RESPONSES = """
CREATE TABLE IF NOT EXISTS responses (
  report_key TEXT PRIMARY KEY,
  text TEXT NOT NULL,
  repository TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL
)"""
_RCOLS = "report_key, text, repository, commit_sha, path, created_at"
_COLS = "key, kind, locator, resolved, rule_pack_version, engine_version, scanned_at, report_json"


class ReportStore(Protocol):
    def get(self, key: str) -> StoredReport | None: ...
    def put(self, rec: StoredReport) -> None: ...
    def previous(self, kind: str, locator: str, before: dt.datetime) -> StoredReport | None: ...
    def prune(self, older_than: dt.datetime) -> int: ...
    def get_response(self, key: str) -> MaintainerResponse | None: ...
    def put_response(self, resp: MaintainerResponse) -> None: ...
    def delete_response(self, key: str) -> None: ...


def _row(r: tuple) -> StoredReport:
    return StoredReport(key=r[0], kind=r[1], locator=r[2], resolved=r[3], rule_pack_version=r[4],
                        engine_version=r[5], scanned_at=dt.datetime.fromisoformat(str(r[6])), report_json=r[7])


def _response(r: tuple) -> MaintainerResponse:
    return MaintainerResponse(report_key=r[0], text=r[1], repository=r[2], commit=r[3], path=r[4],
                              created_at=dt.datetime.fromisoformat(str(r[5])))


class MemoryStore:
    def __init__(self) -> None:
        self._d: dict[str, StoredReport] = {}
        self._responses: dict[str, MaintainerResponse] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> StoredReport | None:
        return self._d.get(key)

    def put(self, rec: StoredReport) -> None:
        with self._lock:
            self._d.setdefault(rec.key, rec)

    def previous(self, kind: str, locator: str, before: dt.datetime) -> StoredReport | None:
        older = [r for r in self._d.values() if r.kind == kind and r.locator == locator and r.scanned_at < before]
        return max(older, key=lambda r: r.scanned_at, default=None)

    def prune(self, older_than: dt.datetime) -> int:
        with self._lock:
            old = [k for k, r in self._d.items() if r.scanned_at < older_than]
            for k in old:
                del self._d[k]
                self._responses.pop(k, None)
        return len(old)

    def get_response(self, key: str) -> MaintainerResponse | None:
        return self._responses.get(key)

    def put_response(self, resp: MaintainerResponse) -> None:
        with self._lock:
            self._responses[resp.report_key] = resp

    def delete_response(self, key: str) -> None:
        with self._lock:
            self._responses.pop(key, None)


class SqliteStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(_SCHEMA)
            self._conn.execute(_INDEX)
            self._conn.execute(_RESPONSES)

    def get(self, key: str) -> StoredReport | None:
        with self._lock:
            r = self._conn.execute(f"SELECT {_COLS} FROM reports WHERE key = ?", (key,)).fetchone()
        return _row(r) if r else None

    def put(self, rec: StoredReport) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT OR IGNORE INTO reports ({_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rec.key, rec.kind, rec.locator, rec.resolved, rec.rule_pack_version, rec.engine_version,
                 rec.scanned_at.isoformat(), rec.report_json),
            )

    def previous(self, kind: str, locator: str, before: dt.datetime) -> StoredReport | None:
        with self._lock:
            r = self._conn.execute(
                f"SELECT {_COLS} FROM reports WHERE kind = ? AND locator = ? AND scanned_at < ? ORDER BY scanned_at DESC LIMIT 1",
                (kind, locator, before.isoformat()),
            ).fetchone()
        return _row(r) if r else None

    def prune(self, older_than: dt.datetime) -> int:
        with self._lock:
            n = self._conn.execute("DELETE FROM reports WHERE scanned_at < ?", (older_than.isoformat(),)).rowcount
            self._conn.execute("DELETE FROM responses WHERE report_key NOT IN (SELECT key FROM reports)")
            return n

    def get_response(self, key: str) -> MaintainerResponse | None:
        with self._lock:
            r = self._conn.execute(f"SELECT {_RCOLS} FROM responses WHERE report_key = ?", (key,)).fetchone()
        return _response(r) if r else None

    def put_response(self, resp: MaintainerResponse) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO responses ({_RCOLS}) VALUES (?, ?, ?, ?, ?, ?)",
                (resp.report_key, resp.text, resp.repository, resp.commit, resp.path, resp.created_at.isoformat()),
            )

    def delete_response(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM responses WHERE report_key = ?", (key,))


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(_SCHEMA.replace("scanned_at TEXT", "scanned_at TIMESTAMPTZ"))
            self._conn.execute(_INDEX)
            self._conn.execute(_RESPONSES.replace("created_at TEXT", "created_at TIMESTAMPTZ"))

    def get(self, key: str) -> StoredReport | None:
        with self._lock:
            r = self._conn.execute(f"SELECT {_COLS} FROM reports WHERE key = %s", (key,)).fetchone()
        return _row(r) if r else None

    def put(self, rec: StoredReport) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT INTO reports ({_COLS}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (key) DO NOTHING",
                (rec.key, rec.kind, rec.locator, rec.resolved, rec.rule_pack_version, rec.engine_version,
                 rec.scanned_at, rec.report_json),
            )

    def previous(self, kind: str, locator: str, before: dt.datetime) -> StoredReport | None:
        with self._lock:
            r = self._conn.execute(
                f"SELECT {_COLS} FROM reports WHERE kind = %s AND locator = %s AND scanned_at < %s ORDER BY scanned_at DESC LIMIT 1",
                (kind, locator, before),
            ).fetchone()
        return _row(r) if r else None

    def prune(self, older_than: dt.datetime) -> int:
        with self._lock:
            n = self._conn.execute("DELETE FROM reports WHERE scanned_at < %s", (older_than,)).rowcount
            self._conn.execute("DELETE FROM responses WHERE report_key NOT IN (SELECT key FROM reports)")
            return n

    def get_response(self, key: str) -> MaintainerResponse | None:
        with self._lock:
            r = self._conn.execute(f"SELECT {_RCOLS} FROM responses WHERE report_key = %s", (key,)).fetchone()
        return _response(r) if r else None

    def put_response(self, resp: MaintainerResponse) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT INTO responses ({_RCOLS}) VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (report_key) DO UPDATE SET text = EXCLUDED.text, repository = EXCLUDED.repository, "
                "commit_sha = EXCLUDED.commit_sha, path = EXCLUDED.path, created_at = EXCLUDED.created_at",
                (resp.report_key, resp.text, resp.repository, resp.commit, resp.path, resp.created_at),
            )

    def delete_response(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM responses WHERE report_key = %s", (key,))


def make_store(url: str) -> ReportStore:
    if url == "memory":
        return MemoryStore()
    if url.startswith("sqlite:///"):
        return SqliteStore(url[len("sqlite:///"):] or ":memory:")
    if url.startswith(("postgresql://", "postgres://")):
        return PostgresStore(url)
    raise ValueError("AGW_STORE must be memory, sqlite:///path or postgresql://...")
