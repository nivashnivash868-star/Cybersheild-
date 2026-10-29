"""Turns rows in your Zetaris-connected log sources into CyberShield security events.

Three sources, each read incrementally with a watermark so a row is never processed twice:

  auth     failed-login bursts, aggregated *inside Zetaris* (GROUP BY ... HAVING), so only suspects come back
  network  flow records, scored by the network anomaly engine
  email    messages, scored by the phishing engine

New events then flow through the normal pipeline: alerts (email/SMS outbox) and cross-source correlation.
Tables and columns are configured in settings (see docs/zetaris-schema.md).
"""
import hashlib
import ipaddress
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditLog, IngestState, SecurityEvent, naive_utc_now
from app.schemas import NetworkRecordInput
from app.services.alert_engine import alert_engine
from app.services.network_engine import network_detector
from app.services.phishing_engine import phishing_detector
from app.services.zetaris import (
    ZetarisClient, ZetarisError, sql_ident, sql_table, sql_timestamp, sql_value,
)

logger = logging.getLogger("cybershield.zetaris.ingest")

SOURCES = ("auth", "network", "email")

DEFAULT_COLUMNS: Dict[str, Dict[str, str]] = {
    "auth": {"event_time": "event_time", "username": "username", "src_ip": "src_ip", "result": "result"},
    "network": {"event_time": "event_time", "src_ip": "src_ip", "dst_ip": "dst_ip", "dst_port": "dst_port",
                "protocol": "protocol", "bytes": "bytes", "packets": "packets"},
    "email": {"event_time": "event_time", "message_id": "message_id", "sender": "sender", "recipient": "recipient",
              "subject": "subject", "body": "body"},
}

_lock = threading.Lock()


def columns(kind: str) -> Dict[str, str]:
    merged = {**DEFAULT_COLUMNS[kind], **(settings.ZETARIS_COLUMNS or {}).get(kind, {})}
    return {k: sql_ident(v) for k, v in merged.items()}


def table(kind: str) -> str:
    return sql_table({"auth": settings.ZETARIS_TABLE_AUTH, "network": settings.ZETARIS_TABLE_NETWORK,
                      "email": settings.ZETARIS_TABLE_EMAIL}[kind])


def configured_sources() -> List[str]:
    return [k for k, t in (("auth", settings.ZETARIS_TABLE_AUTH), ("network", settings.ZETARIS_TABLE_NETWORK),
                           ("email", settings.ZETARIS_TABLE_EMAIL)) if t]


_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(value: Any) -> Optional[datetime]:
    """Naive UTC datetime from the formats Zetaris/Spark/Trino return, including '2026-10-28 10:13:12.0' (any number
    of fractional digits), ISO strings with 'T' or 'Z', and epoch seconds/milliseconds. Spark's timestamps carry no
    zone and are taken as UTC, which is what the JVM in the Zetaris container uses."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc).replace(tzinfo=None)
    text = str(value).strip()
    if re.fullmatch(r"\d{9,13}(\.\d+)?", text):
        return parse_time(float(text))
    m = _TIME_RE.match(text)
    if not m:
        return None
    y, mo, d, h, mi, sec, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), micro)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return dt


def severity_for(score: int) -> str:
    return "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 35 else "Low"


def _stable_id(prefix: str, *parts: Any) -> str:
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:14].upper()
    return f"{prefix}-{digest}"


def _state(db: Session, source: str) -> IngestState:
    row = db.query(IngestState).filter(IngestState.source == source).first()
    if row is None:
        row = IngestState(source=source, watermark=naive_utc_now() - timedelta(hours=settings.ZETARIS_INITIAL_LOOKBACK_HOURS))
        db.add(row)
        db.flush()
    return row


def _emit(db: Session, *, event_id: str, source_label: str, category: str, score: int, severity: str,
          timestamp: Optional[datetime] = None, source_ip: Optional[str] = None, dest_ip: Optional[str] = None,
          domain: Optional[str] = None, user: Optional[str] = None, evidence: str, action: str) -> Optional[SecurityEvent]:
    if any(isinstance(o, SecurityEvent) and o.event_id == event_id for o in db.new):
        return None  # duplicate within this pass (autoflush is off, so pending rows are checked here)
    if db.query(SecurityEvent.id).filter(SecurityEvent.event_id == event_id).first():
        return None  # already ingested in an earlier pass (idempotent)
    event = SecurityEvent(
        event_id=event_id, timestamp=timestamp or naive_utc_now(), event_source=source_label, threat_category=category,
        risk_score=score, severity=severity, source_ip=source_ip, dest_ip=dest_ip, domain=domain, user_account=user,
        evidence=evidence[:4000], analysis_status="Analyzed", recommended_action=action,
        is_simulated=settings.ZETARIS_DATA_IS_SYNTHETIC,
    )
    db.add(event)
    if severity in ("High", "Critical"):
        target = user if user and re.match(r"^[^@\s]+@[^@\s]+$", user) else None
        alert_engine.dispatch_security_alert(
            db, title=f"{category}" + (f" from {source_ip}" if source_ip else ""), sanitized_summary=evidence[:500],
            severity=severity, target_employee_email=target, event_id=event_id,
        )
    return event


# --- per-source ingestion ---------------------------------------------------------------------------------------------
def _outcome_in(column: str, csv_values: str) -> str:
    """`UPPER(col) IN ('A','B')`: the configured spellings of an outcome, compared without regard to case."""
    values = [v.strip().upper() for v in csv_values.split(",") if v.strip()]
    if not values:
        raise ValueError("No outcome values configured for the auth table.")
    return f"UPPER({column}) IN ({', '.join(sql_value(v) for v in values)})"


def _auth_floor() -> int:
    low = settings.ZETARIS_LOW_SIGNAL_THRESHOLD
    return max(1, min(low, settings.ZETARIS_BRUTE_FORCE_THRESHOLD)) if low > 0 else settings.ZETARIS_BRUTE_FORCE_THRESHOLD


def _ingest_auth(db: Session, client: ZetarisClient, state: IngestState) -> Dict[str, int]:
    c, t, wm = columns("auth"), table("auth"), sql_timestamp(state.watermark)
    newest = client.query(f"SELECT MAX({c['event_time']}) AS newest FROM {t} WHERE {c['event_time']} > {wm}", max_rows=1)
    newest_ts = parse_time(newest[0].get("newest")) if newest else None
    if newest_ts is None:
        return {"rows": 0, "events": 0}
    # Aggregation runs inside Zetaris: only (ip, user) pairs with a burst of failures come back.
    groups = client.query(
        f"SELECT {c['src_ip']} AS src_ip, {c['username']} AS username, COUNT(*) AS failures, "
        f"MIN({c['event_time']}) AS first_seen, MAX({c['event_time']}) AS last_seen FROM {t} "
        f"WHERE {_outcome_in(c['result'], settings.ZETARIS_AUTH_FAILURE_VALUES)} AND {c['event_time']} > {wm} AND {c['event_time']} <= {sql_timestamp(newest_ts)} "
        f"GROUP BY {c['src_ip']}, {c['username']} HAVING COUNT(*) >= {int(_auth_floor())} "
        f"ORDER BY failures DESC",
        max_rows=500,
    )
    created = 0
    for g in groups:
        ip, user, failures = str(g.get("src_ip")), str(g.get("username")), int(g.get("failures") or 0)
        try:
            internal = ipaddress.ip_address(ip).is_private
        except ValueError:
            internal = False
        first, last = parse_time(g.get("first_seen")), parse_time(g.get("last_seen"))
        # People mistype passwords from their own network far more often than attackers appear from it. Small or
        # internal bursts are still reported, as Low alerts, so L1 triage can close them and leave a record.
        threshold = settings.ZETARIS_BRUTE_FORCE_THRESHOLD * (settings.ZETARIS_INTERNAL_FAILURE_MULTIPLIER if internal else 1)
        if failures < threshold:
            ev = _emit(
                db, event_id=_stable_id("ZT-AUTH", ip, user, first), source_label="Zetaris / auth logs",
                category="Failed Login Burst", score=min(30, 15 + failures * 3), severity="Low", timestamp=last, source_ip=ip,
                user=user, evidence=f"{failures} failed logins for '{user}' from {'internal' if internal else 'external'} "
                                    f"address {ip} between {first} and {last} UTC.",
                action="No action unless it repeats.")
            created += 1 if ev else 0
            continue
        compromised = False
        if not internal:
            try:  # an outside address that failed repeatedly and then got in is a likely compromise
                hit = client.query(
                    f"SELECT COUNT(*) AS n FROM {t} WHERE {_outcome_in(c['result'], settings.ZETARIS_AUTH_SUCCESS_VALUES)} AND {c['src_ip']} = {sql_value(ip)} "
                    f"AND {c['username']} = {sql_value(user)} AND {c['event_time']} >= {sql_timestamp(last or newest_ts)}",
                    max_rows=1)
                compromised = bool(hit and int(hit[0].get("n") or 0) > 0)
            except (ZetarisError, ValueError):
                pass
        score = 95 if compromised else min(90, 55 + failures * 2)
        category = "Account Compromise Suspected" if compromised else "Credential Brute Force"
        evidence = (f"{failures} failed logins for '{user}' from {'internal' if internal else 'external'} address {ip} "
                    f"between {first} and {last} UTC"
                    + ("; followed by a SUCCESSFUL login from the same address." if compromised else "."))
        ev = _emit(
            db, event_id=_stable_id("ZT-AUTH", ip, user, first), source_label="Zetaris / auth logs", category=category,
            score=score, severity=severity_for(score), timestamp=last, source_ip=ip, user=user, evidence=evidence,
            action=("Reset the account's credentials, revoke its sessions and block the source address."
                    if compromised else "Confirm the account is protected by MFA and investigate the source."),
        )
        created += 1 if ev else 0
    state.watermark = newest_ts
    return {"rows": len(groups), "events": created}


def _ingest_network(db: Session, client: ZetarisClient, state: IngestState) -> Dict[str, int]:
    c, t = columns("network"), table("network")
    rows_total, created = 0, 0
    for _ in range(max(1, settings.ZETARIS_MAX_BATCHES_PER_PASS)):  # catch up in bounded batches
        rows = client.query(
            f"SELECT {c['event_time']} AS event_time, {c['src_ip']} AS src_ip, {c['dst_ip']} AS dst_ip, "
            f"{c['dst_port']} AS dst_port, {c['protocol']} AS protocol, {c['bytes']} AS bytes, {c['packets']} AS packets "
            f"FROM {t} WHERE {c['event_time']} > {sql_timestamp(state.watermark)} ORDER BY {c['event_time']} "
            f"LIMIT {int(settings.ZETARIS_BATCH_ROWS)}",
            max_rows=settings.ZETARIS_BATCH_ROWS)
        if not rows:
            break
        rows_total += len(rows)
        records, newest = [], state.watermark
        for r in rows:
            ts = parse_time(r.get("event_time"))
            if ts and ts > newest:
                newest = ts
            try:
                records.append(NetworkRecordInput(
                    timestamp=str(r.get("event_time")), source_ip=str(r["src_ip"]), destination_ip=str(r["dst_ip"]),
                    destination_port=int(r.get("dst_port") or 0), protocol=str(r.get("protocol") or "TCP"),
                    bytes_transferred=int(r.get("bytes") or 0), packet_count=int(r.get("packets") or 1)))
            except (KeyError, ValueError, TypeError):
                continue
        for a in network_detector.analyze_batch(records, include_ml=settings.ZETARIS_NETWORK_INCLUDE_ML_OUTLIERS).alerts:
            if a.event_type.startswith("Multivariate") and not settings.ZETARIS_NETWORK_INCLUDE_ML_OUTLIERS:
                continue
            ev = _emit(
                db, event_id=_stable_id("ZT-NET", a.event_type, a.source_ip, a.destination_ip, newest.strftime("%Y%m%d%H")),
                source_label="Zetaris / network flows", category=a.event_type, score=a.risk_score, severity=a.severity,
                timestamp=parse_time(a.timestamp), source_ip=a.source_ip, dest_ip=a.destination_ip,
                evidence=f"{a.detection_reason} Evidence: {', '.join(a.evidence_tokens)}", action=a.recommended_response)
            created += 1 if ev else 0
        db.flush()
        if newest <= state.watermark:
            break
        state.watermark = newest
        if len(rows) < settings.ZETARIS_BATCH_ROWS:
            break
    return {"rows": rows_total, "events": created}


def _ingest_email(db: Session, client: ZetarisClient, state: IngestState) -> Dict[str, int]:
    c, t = columns("email"), table("email")
    rows = client.query(
        f"SELECT {c['event_time']} AS event_time, {c['message_id']} AS message_id, {c['sender']} AS sender, "
        f"{c['recipient']} AS recipient, {c['subject']} AS subject, {c['body']} AS body FROM {t} "
        f"WHERE {c['event_time']} > {sql_timestamp(state.watermark)} ORDER BY {c['event_time']} "
        f"LIMIT {int(settings.ZETARIS_BATCH_ROWS) // 4}",
        max_rows=settings.ZETARIS_BATCH_ROWS // 4)
    created, newest = 0, state.watermark
    for r in rows:
        ts = parse_time(r.get("event_time"))
        if ts and ts > newest:
            newest = ts
        body = str(r.get("body") or "")
        result = phishing_detector.analyze_message(
            content=body or str(r.get("subject") or ""), submission_type="email",
            email_subject=str(r.get("subject") or ""), sender_info=str(r.get("sender") or ""))
        if result.risk_score < 35:
            continue
        ev = _emit(
            db, event_id=_stable_id("ZT-MAIL", r.get("message_id"), r.get("recipient")),
            source_label="Zetaris / email gateway", category=f"Phishing / {result.risk_category} Risk",
            score=result.risk_score, severity=result.risk_category, timestamp=ts, user=str(r.get("recipient") or "") or None,
            domain=result.features_extracted.get("hostname") if isinstance(result.features_extracted, dict) else None,
            evidence=f"From {r.get('sender')}: {result.explanation}",
            action=result.recommended_precautions[0] if result.recommended_precautions else "Quarantine and review.")
        created += 1 if ev else 0
    state.watermark = newest
    return {"rows": len(rows), "events": created}


_RUNNERS: Dict[str, Callable[[Session, ZetarisClient, IngestState], Dict[str, int]]] = {
    "auth": _ingest_auth, "network": _ingest_network, "email": _ingest_email,
}


def run_ingest(db: Session, client: ZetarisClient) -> Dict[str, Any]:
    """One pass over every configured source. A failing source is recorded and does not stop the others."""
    if not _lock.acquire(blocking=False):
        return {"status": "busy", "sources": {}}
    try:
        report: Dict[str, Any] = {}
        total_events, correlated = 0, 0
        for source in configured_sources():
            state = _state(db, source)
            state.last_run_at = naive_utc_now()
            try:
                stats = _RUNNERS[source](db, client, state)
                state.last_status, state.last_error = "OK", None
                state.rows_seen += stats["rows"]
                state.events_created += stats["events"]
                total_events += stats["events"]
                report[source] = {"status": "OK", **stats}
                db.commit()
            except (ZetarisError, ValueError) as exc:
                db.rollback()
                state = _state(db, source)
                state.last_run_at, state.last_status, state.last_error = naive_utc_now(), "ERROR", str(exc)[:500]
                report[source] = {"status": "ERROR", "error": str(exc)[:200]}
                db.commit()
                logger.warning("Zetaris ingest of %s failed: %s", source, exc)
        if total_events:  # new events are triaged by L1 and investigated by L2 on the next automation cycle
            db.add(AuditLog(action="ZETARIS_INGEST", actor="System", resource_type="Zetaris", resource_id="ingest",
                            details=f"Created {total_events} events for SOC triage."))
            db.commit()
        return {"status": "ok", "events_created": total_events, "correlated_incidents": correlated, "sources": report}
    finally:
        _lock.release()


# --- investigation --------------------------------------------------------------------------------------------------
_USER_RE = re.compile(r"^[A-Za-z0-9@._+\-]{1,128}$")


def classify_indicator(raw: str) -> str:
    value = raw.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _USER_RE.match(value):
        return "user"
    raise ValueError("Enter an IP address, a username or an email address.")


def investigate(client: ZetarisClient, indicator: str, *, limit: int = 200) -> Dict[str, Any]:
    """Pulls everything the connected sources know about one IP or user and returns a merged timeline."""
    kind = classify_indicator(indicator)
    value = sql_value(indicator.strip())
    since = sql_timestamp(naive_utc_now() - timedelta(hours=settings.ZETARIS_INITIAL_LOOKBACK_HOURS))
    timeline: List[Dict[str, Any]] = []
    sources_used: List[str] = []
    stats: Dict[str, Any] = {}

    if settings.ZETARIS_TABLE_AUTH:
        c, t = columns("auth"), table("auth")
        cond = f"{c['src_ip']} = {value}" if kind == "ip" else f"{c['username']} = {value}"
        rows = client.query(f"SELECT {c['event_time']} AS event_time, {c['username']} AS username, {c['src_ip']} AS src_ip, "
                            f"{c['result']} AS result FROM {t} WHERE {cond} AND {c['event_time']} > {since} "
                            f"ORDER BY {c['event_time']} LIMIT {limit}", max_rows=limit)
        sources_used.append("auth")
        fails = sum(1 for r in rows if str(r.get("result")).upper() == "FAILURE")
        stats["failed_logins"], stats["successful_logins"] = fails, len(rows) - fails
        timeline += [{"time": str(r.get("event_time")), "source": "auth", "ip": r.get("src_ip"),
                      "summary": f"{r.get('result')} login for {r.get('username')} from {r.get('src_ip')}"} for r in rows]

    if settings.ZETARIS_TABLE_NETWORK:
        c, t = columns("network"), table("network")
        cond = f"({c['src_ip']} = {value} OR {c['dst_ip']} = {value})" if kind == "ip" else None
        if cond:
            rows = client.query(f"SELECT {c['event_time']} AS event_time, {c['src_ip']} AS src_ip, {c['dst_ip']} AS dst_ip, "
                                f"{c['dst_port']} AS dst_port, {c['bytes']} AS bytes FROM {t} WHERE {cond} "
                                f"AND {c['event_time']} > {since} ORDER BY {c['event_time']} LIMIT {limit}", max_rows=limit)
            sources_used.append("network")
            stats["flows"] = len(rows)
            stats["bytes_transferred"] = sum(int(r.get("bytes") or 0) for r in rows)
            timeline += [{"time": str(r.get("event_time")), "source": "network", "ip": r.get("src_ip"),
                          "summary": f"{r.get('src_ip')} -> {r.get('dst_ip')}:{r.get('dst_port')} ({int(r.get('bytes') or 0)} bytes)"}
                         for r in rows]

    if settings.ZETARIS_TABLE_EMAIL:
        c, t = columns("email"), table("email")
        cond = f"({c['sender']} = {value} OR {c['recipient']} = {value})" if kind == "user" else None
        if cond:
            rows = client.query(f"SELECT {c['event_time']} AS event_time, {c['sender']} AS sender, {c['recipient']} AS recipient, "
                                f"{c['subject']} AS subject FROM {t} WHERE {cond} AND {c['event_time']} > {since} "
                                f"ORDER BY {c['event_time']} LIMIT {limit}", max_rows=limit)
            sources_used.append("email")
            stats["emails"] = len(rows)
            timeline += [{"time": str(r.get("event_time")), "source": "email", "ip": None,
                          "summary": f"Email from {r.get('sender')} to {r.get('recipient')}: {r.get('subject')}"} for r in rows]

    timeline.sort(key=lambda e: e["time"])
    suggested = []
    if kind == "ip" and (stats.get("failed_logins", 0) >= settings.ZETARIS_BRUTE_FORCE_THRESHOLD
                         or stats.get("bytes_transferred", 0) > 50_000_000):
        suggested.append({"indicator": indicator.strip(), "reason": (
            f"Seen in Zetaris sources: {stats.get('failed_logins', 0)} failed logins, "
            f"{stats.get('flows', 0)} flows, {stats.get('bytes_transferred', 0)} bytes.")})
    return {"indicator": indicator.strip(), "type": kind, "sources_queried": sources_used, "stats": stats,
            "timeline": timeline[-limit:], "suggested_blocks": suggested}


# --- previewing a source before trusting it -------------------------------------------------------------------------------
def preview(client: ZetarisClient, source: str, limit: int = 5) -> Dict[str, Any]:
    """Read a few of the newest rows of a configured table and say whether CyberShield understands them. Writes nothing.
    Meant for the first connection to real logs: wrong column names, unreadable timestamps or an unexpected outcome
    vocabulary are the usual reasons a pipeline silently finds nothing."""
    if source not in SOURCES or source not in configured_sources():
        raise ValueError("That source is not configured.")
    c, t = columns(source), table(source)
    cols = ", ".join(f"{col} AS {key}" for key, col in c.items())
    rows = client.query(f"SELECT {cols} FROM {t} ORDER BY {c['event_time']} DESC LIMIT {int(max(1, min(limit, 20)))}", max_rows=20)
    out: Dict[str, Any] = {"source": source, "table": t, "columns": c, "sample_rows": [], "warnings": []}
    parsed = 0
    for r in rows:
        out["sample_rows"].append({k: (str(v)[:120] if v is not None else None) for k, v in r.items()})
        parsed += 1 if parse_time(r.get("event_time")) else 0
    out["timestamps_read"] = f"{parsed}/{len(rows)}"
    if not rows:
        out["warnings"].append("The table returned no rows.")
    elif parsed < len(rows):
        out["warnings"].append("Some event_time values could not be read; CyberShield expects 'YYYY-MM-DD HH:MM:SS[.f]', ISO 8601 or epoch values.")
    since = client.query(f"SELECT COUNT(*) AS n FROM {t} WHERE {c['event_time']} > {sql_timestamp(naive_utc_now() - timedelta(hours=24))}", max_rows=1)
    out["rows_last_24h"] = int((since[0].get("n") if since else 0) or 0)
    if rows and out["rows_last_24h"] == 0:
        out["warnings"].append("No rows in the last 24 hours: timestamps may be in another time zone, or the feed has stopped.")
    if source == "auth":
        dist = client.query(f"SELECT {c['result']} AS value, COUNT(*) AS n FROM {t} GROUP BY {c['result']} ORDER BY n DESC LIMIT 10", max_rows=10)
        out["outcome_values"] = [{"value": str(d.get("value")), "count": int(d.get("n") or 0)} for d in dist]
        fail = {v.strip().upper() for v in settings.ZETARIS_AUTH_FAILURE_VALUES.split(",") if v.strip()}
        known = fail | {v.strip().upper() for v in settings.ZETARIS_AUTH_SUCCESS_VALUES.split(",") if v.strip()}
        seen = {str(d.get("value")).upper() for d in dist}
        out["failure_values_matched"] = sorted(seen & fail)
        if not seen & fail:
            out["warnings"].append("None of the outcome values in the table match ZETARIS_AUTH_FAILURE_VALUES, so no failed-login burst will ever be found. "
                                   "Add the table's spelling of 'failed' to that setting.")
        unknown = sorted(seen - known)
        if unknown:
            out["warnings"].append(f"Outcome values not classified as success or failure: {', '.join(unknown[:6])}.")
    if source == "network":
        bad = sum(1 for r in rows if not str(r.get("dst_port", "")).lstrip("-").isdigit() or not str(r.get("bytes", "")).lstrip("-").isdigit())
        if bad:
            out["warnings"].append("Some dst_port / bytes values are not whole numbers; those flows are skipped.")
    return out
