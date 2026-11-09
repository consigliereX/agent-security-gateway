from __future__ import annotations

import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class ApprovalRecord:
    approval_id: str
    session_id: str
    turn_id: str
    agent_id: str
    action_fingerprint: str
    action_type: str
    action_target: str
    status: str
    created_at: str
    expires_at: str
    resolved_at: Optional[str] = None
    resolver: str = ""
    resolution_note: str = ""
    permit_token: str = ""
    permit_expires_at: Optional[str] = None


class SQLiteApprovalStore:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._closed = False
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_fingerprint TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolver TEXT NOT NULL,
                    resolution_note TEXT NOT NULL,
                    permit_token TEXT NOT NULL,
                    permit_expires_at TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approvals_fingerprint ON approvals(action_fingerprint, session_id, status)"
            )
            self._conn.execute("DROP INDEX IF EXISTS idx_approvals_permit")
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_permit_nonempty ON approvals(permit_token) WHERE permit_token != ''"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approvals_recent ON approvals(created_at DESC, approval_id DESC)"
            )
            self._conn.commit()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=str(row["approval_id"]),
            session_id=str(row["session_id"]),
            turn_id=str(row["turn_id"]),
            agent_id=str(row["agent_id"]),
            action_fingerprint=str(row["action_fingerprint"]),
            action_type=str(row["action_type"]),
            action_target=str(row["action_target"]),
            status=str(row["status"]),
            created_at=str(row["created_at"]),
            expires_at=str(row["expires_at"]),
            resolved_at=str(row["resolved_at"]) if row["resolved_at"] else None,
            resolver=str(row["resolver"]),
            resolution_note=str(row["resolution_note"]),
            permit_token=str(row["permit_token"]),
            permit_expires_at=str(row["permit_expires_at"]) if row["permit_expires_at"] else None,
        )

    def _save(self, record: ApprovalRecord) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, session_id, turn_id, agent_id,
                    action_fingerprint, action_type, action_target,
                    status, created_at, expires_at, resolved_at,
                    resolver, resolution_note, permit_token, permit_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(approval_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    turn_id=excluded.turn_id,
                    agent_id=excluded.agent_id,
                    action_fingerprint=excluded.action_fingerprint,
                    action_type=excluded.action_type,
                    action_target=excluded.action_target,
                    status=excluded.status,
                    created_at=excluded.created_at,
                    expires_at=excluded.expires_at,
                    resolved_at=excluded.resolved_at,
                    resolver=excluded.resolver,
                    resolution_note=excluded.resolution_note,
                    permit_token=excluded.permit_token,
                    permit_expires_at=excluded.permit_expires_at
                """,
                (
                    record.approval_id,
                    record.session_id,
                    record.turn_id,
                    record.agent_id,
                    record.action_fingerprint,
                    record.action_type,
                    record.action_target,
                    record.status,
                    record.created_at,
                    record.expires_at,
                    record.resolved_at,
                    record.resolver,
                    record.resolution_note,
                    record.permit_token,
                    record.permit_expires_at,
                ),
            )
            self._conn.commit()

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
            row = cur.fetchone()
        if row is None:
            return None
        record = self._row_to_record(row)
        return self._expire_if_needed(record)

    def list_recent(self, limit: int = 100) -> List[ApprovalRecord]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM approvals ORDER BY created_at DESC, approval_id DESC LIMIT ?",
                (capped,),
            ).fetchall()
        return [self._expire_if_needed(self._row_to_record(row)) for row in rows]

    def list_pending(self, limit: int = 100) -> List[ApprovalRecord]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM approvals
                WHERE status = 'pending'
                ORDER BY created_at DESC, approval_id DESC
                LIMIT ?
                """,
                (capped,),
            ).fetchall()
        pending: List[ApprovalRecord] = []
        for row in rows:
            rec = self._expire_if_needed(self._row_to_record(row))
            if rec.status == "pending":
                pending.append(rec)
        return pending

    def get_or_create_pending(
        self,
        *,
        session_id: str,
        turn_id: str,
        agent_id: str,
        action_fingerprint: str,
        action_type: str,
        action_target: str,
        expires_in_seconds: int = 900,
    ) -> ApprovalRecord:
        now = self._now()
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT * FROM approvals
                WHERE session_id = ? AND action_fingerprint = ? AND status = 'pending'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (session_id, action_fingerprint),
            )
            row = cur.fetchone()
        if row is not None:
            record = self._row_to_record(row)
            record = self._expire_if_needed(record)
            if record.status == "pending":
                return record

        approval_id = secrets.token_urlsafe(16)
        expires_at = (now + timedelta(seconds=max(1, int(expires_in_seconds)))).isoformat()
        record = ApprovalRecord(
            approval_id=approval_id,
            session_id=session_id,
            turn_id=turn_id,
            agent_id=agent_id,
            action_fingerprint=action_fingerprint,
            action_type=action_type,
            action_target=action_target,
            status="pending",
            created_at=now.isoformat(),
            expires_at=expires_at,
        )
        self._save(record)
        return record

    def resolve(
        self,
        *,
        approval_id: str,
        approve: bool,
        resolver: str,
        note: str,
        permit_ttl_seconds: int = 300,
    ) -> ApprovalRecord:
        record = self.get(approval_id)
        if record is None:
            raise ValueError("approval_id not found")
        if record.status != "pending":
            raise ValueError(f"approval is not pending: {record.status}")

        now = self._now()
        if approve:
            token = secrets.token_urlsafe(24)
            permit_expires_at = (now + timedelta(seconds=max(0, int(permit_ttl_seconds)))).isoformat()
            status = "approved"
        else:
            token = ""
            permit_expires_at = None
            status = "denied"

        updated = ApprovalRecord(
            approval_id=record.approval_id,
            session_id=record.session_id,
            turn_id=record.turn_id,
            agent_id=record.agent_id,
            action_fingerprint=record.action_fingerprint,
            action_type=record.action_type,
            action_target=record.action_target,
            status=status,
            created_at=record.created_at,
            expires_at=record.expires_at,
            resolved_at=now.isoformat(),
            resolver=resolver,
            resolution_note=note,
            permit_token=token,
            permit_expires_at=permit_expires_at,
        )
        self._save(updated)
        return updated

    def consume_permit(
        self,
        *,
        permit_token: str,
        session_id: str,
        agent_id: str,
        action_fingerprint: str,
    ) -> Optional[ApprovalRecord]:
        if not permit_token.strip():
            return None
        # A conditional UPDATE provides one-time consumption even when two
        # processes concurrently attempt to use the same permit.
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE permit_token = ?", (permit_token,)
            ).fetchone()
            if row is None:
                return None
            record = self._row_to_record(row)
            if (
                record.status != "approved"
                or record.session_id != session_id
                or record.agent_id != agent_id
                or record.action_fingerprint != action_fingerprint
            ):
                return None
            expiry = datetime.fromisoformat(record.permit_expires_at) if record.permit_expires_at else self._now()
            if self._now() > expiry:
                self._conn.execute(
                    "UPDATE approvals SET status = 'expired' WHERE approval_id = ? AND status = 'approved'",
                    (record.approval_id,),
                )
                self._conn.commit()
                return None
            cursor = self._conn.execute(
                "UPDATE approvals SET status = 'used' WHERE approval_id = ? AND status = 'approved'",
                (record.approval_id,),
            )
            self._conn.commit()
            if cursor.rowcount != 1:
                return None
            return ApprovalRecord(**{**record.__dict__, "status": "used"})

    def _expire_if_needed(self, record: ApprovalRecord) -> ApprovalRecord:
        if record.status != "pending":
            return record
        if self._now() <= datetime.fromisoformat(record.expires_at):
            return record
        expired = ApprovalRecord(**{**record.__dict__, "status": "expired"})
        self._save(expired)
        return expired

    def ping(self) -> bool:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._conn.close()
            finally:
                self._closed = True




