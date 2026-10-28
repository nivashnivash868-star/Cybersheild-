"""Tamper-evident audit log.

Every AuditLog row gets prev_hash/entry_hash on flush, where entry_hash = HMAC(SECRET_KEY, prev_hash + record).
Editing, deleting or reordering a past row breaks every hash after it, and without SECRET_KEY the chain can't
be recomputed. Call sites keep using AuditLog(...) unchanged.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.utils.context import client_ip_var, request_id_var
from app.utils.crypto import hmac_hex

GENESIS = "0" * 64
_LOCK_ID = 727274


def _canonical(row: AuditLog, prev_hash: str) -> str:
    ts = row.timestamp
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return json.dumps(
        [prev_hash, ts.isoformat(), row.action, row.actor, row.resource_type, row.resource_id,
         row.details or "", row.request_id or "", row.ip_address or ""],
        separators=(",", ":"),
    )


def compute_hash(row: AuditLog, prev_hash: str) -> str:
    return hmac_hex("audit-v1", _canonical(row, prev_hash))


@event.listens_for(Session, "before_flush")
def _chain_audit_rows(session: Session, flush_context: Any, instances: Any) -> None:
    new_rows: List[AuditLog] = [o for o in session.new if isinstance(o, AuditLog)]
    if not new_rows:
        return
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_ID})
    last = session.query(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1).scalar()
    prev = last or GENESIS
    for row in new_rows:
        if row.timestamp is None:
            row.timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
        if row.request_id is None:
            row.request_id = request_id_var.get()
        if row.ip_address is None:
            row.ip_address = client_ip_var.get()
        row.prev_hash = prev
        row.entry_hash = compute_hash(row, prev)
        prev = row.entry_hash


def verify_chain(db: Session) -> Dict[str, Any]:
    prev = GENESIS
    count = 0
    for row in db.query(AuditLog).order_by(AuditLog.id.asc()).yield_per(500):
        if row.entry_hash is None:  # rows written before the chain existed
            continue
        if row.prev_hash != prev or compute_hash(row, prev) != row.entry_hash:
            return {"valid": False, "checked": count, "first_bad_id": row.id}
        prev = row.entry_hash
        count += 1
    return {"valid": True, "checked": count, "first_bad_id": None}
