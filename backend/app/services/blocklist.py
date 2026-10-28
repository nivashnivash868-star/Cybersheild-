"""Blocklist: the platform's real prevention control.

Analysts propose indicators (IP, CIDR, domain, URL); an administrator approves; approved entries are published
in authenticated pull feeds that a firewall, proxy or DNS sinkhole consumes (Palo Alto EDL, Fortinet threat feed,
pfSense pfBlockerNG, Squid/Pi-hole lists all accept this plain-text format). The platform never holds firewall
credentials. Entries expire automatically, and indicators that would cut off your own infrastructure are refused.
"""
import hashlib
import ipaddress
import re
from datetime import timedelta
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditLog, BlocklistEntry, naive_utc_now

_HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Blocking these would break most of the internet for the organisation, so they can never be listed.
_NEVER_BLOCK = {
    "google.com", "microsoft.com", "office.com", "live.com", "apple.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "github.com", "okta.com", "slack.com", "zoom.us",
}
MIN_V4_PREFIX = 16
MIN_V6_PREFIX = 48


def _protected_networks() -> List[ipaddress._BaseNetwork]:
    nets = []
    for item in settings.BLOCKLIST_PROTECTED:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


def _protected_domains() -> set:
    out = set(_NEVER_BLOCK)
    for item in settings.BLOCKLIST_PROTECTED:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            out.add(item.lower().strip("."))
    return out


def _is_protected_domain(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _protected_domains())


def _refuse(msg: str) -> HTTPException:
    return HTTPException(status_code=422, detail=msg)


def normalise_indicator(raw: str, indicator_type: Optional[str] = None) -> Tuple[str, str]:
    """Returns (type, canonical value) or raises 422. Type is inferred when not given."""
    value = raw.strip()
    if not value or len(value) > 512 or any(c in value for c in "\r\n\t "):
        raise _refuse("Indicator is empty, too long or contains whitespace.")

    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise _refuse("Only http(s) URLs can be blocked.")
        host = parts.hostname.lower().rstrip(".")
        _check_host(host)
        path = parts.path or "/"
        canon = f"{parts.scheme}://{host}{(':' + str(parts.port)) if parts.port else ''}{path}"
        if parts.query:
            canon += "?" + parts.query
        return "url", canon

    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            _check_network(net)
            return "cidr", str(net)
        ip = ipaddress.ip_address(value)
        _check_network(ipaddress.ip_network(ip))
        return "ip", str(ip)
    except ValueError:
        pass

    host = value.lower().rstrip(".")
    _check_host(host)
    return "domain", host


def _check_network(net) -> None:
    if not (net.network_address.is_global and net[-1].is_global):
        raise _refuse("Private, loopback, link-local, multicast and reserved ranges can't be blocked.")
    min_prefix = MIN_V4_PREFIX if net.version == 4 else MIN_V6_PREFIX
    if net.prefixlen < min_prefix:
        raise _refuse(f"Range is too broad: the shortest allowed prefix is /{min_prefix}.")
    for protected in _protected_networks():
        if protected.version == net.version and protected.overlaps(net):
            raise _refuse("This range overlaps a protected network.")


def _check_host(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        _check_network(ipaddress.ip_network(ip))
        return
    if not _HOST.match(host):
        raise _refuse("That is not a valid domain name.")
    if host.endswith((".local", ".internal", ".corp", ".lan", ".test", ".localhost", ".invalid", ".example")):
        raise _refuse("Internal or reserved domain names can't be blocked.")
    if _is_protected_domain(host):
        raise _refuse("This domain is on the never-block list.")


def clamp_ttl(ttl_hours: Optional[int]) -> int:
    ttl = ttl_hours or settings.BLOCKLIST_DEFAULT_TTL_HOURS
    if ttl < 1:
        raise _refuse("TTL must be at least 1 hour.")
    return min(ttl, settings.BLOCKLIST_MAX_TTL_HOURS)


def propose(db: Session, raw: str, reason: str, actor_name: str, *, auto_approve: bool,
            incident_id: Optional[str] = None, ttl_hours: Optional[int] = None,
            indicator_type: Optional[str] = None) -> Tuple[BlocklistEntry, bool]:
    itype, value = normalise_indicator(raw, indicator_type)
    existing = db.query(BlocklistEntry).filter(
        BlocklistEntry.indicator_type == itype, BlocklistEntry.value == value,
        BlocklistEntry.status.in_(("PENDING_APPROVAL", "ACTIVE")),
    ).first()
    if existing:
        return existing, False
    now = naive_utc_now()
    entry = BlocklistEntry(
        indicator_type=itype, value=value, reason=reason.strip()[:2000], incident_id=incident_id,
        ttl_hours=clamp_ttl(ttl_hours), proposed_by=actor_name, proposed_at=now,
    )
    db.add(entry)
    db.flush()
    db.add(AuditLog(action="BLOCKLIST_PROPOSED", actor=actor_name, resource_type="BlocklistEntry",
                    resource_id=str(entry.id), details=f"{itype} {value} proposed (TTL {entry.ttl_hours}h): {entry.reason[:200]}"))
    if auto_approve:
        approve(db, entry, actor_name, "Proposed by an administrator.")
    return entry, True


def approve(db: Session, entry: BlocklistEntry, actor_name: str, note: Optional[str] = None) -> None:
    if entry.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=409, detail=f"Entry is {entry.status}, not pending approval.")
    now = naive_utc_now()
    entry.status = "ACTIVE"
    entry.decided_by, entry.decided_at, entry.decision_note = actor_name, now, (note or "")[:500]
    entry.activated_at = now
    entry.expires_at = now + timedelta(hours=entry.ttl_hours)
    db.add(AuditLog(action="BLOCKLIST_APPROVED", actor=actor_name, resource_type="BlocklistEntry",
                    resource_id=str(entry.id), details=f"{entry.indicator_type} {entry.value} published until {entry.expires_at} UTC."))


def reject(db: Session, entry: BlocklistEntry, actor_name: str, note: Optional[str] = None) -> None:
    if entry.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=409, detail=f"Entry is {entry.status}, not pending approval.")
    entry.status = "REJECTED"
    entry.decided_by, entry.decided_at, entry.decision_note = actor_name, naive_utc_now(), (note or "")[:500]
    db.add(AuditLog(action="BLOCKLIST_REJECTED", actor=actor_name, resource_type="BlocklistEntry",
                    resource_id=str(entry.id), details=f"{entry.indicator_type} {entry.value} rejected."))


def revoke(db: Session, entry: BlocklistEntry, actor_name: str, note: Optional[str] = None) -> None:
    if entry.status != "ACTIVE":
        raise HTTPException(status_code=409, detail=f"Entry is {entry.status}, not active.")
    entry.status = "REVOKED"
    entry.decided_by, entry.decided_at, entry.decision_note = actor_name, naive_utc_now(), (note or "")[:500]
    db.add(AuditLog(action="BLOCKLIST_REVOKED", actor=actor_name, resource_type="BlocklistEntry",
                    resource_id=str(entry.id), details=f"{entry.indicator_type} {entry.value} removed from feeds."))


def expire_due(db: Session) -> int:
    now = naive_utc_now()
    due = db.query(BlocklistEntry).filter(BlocklistEntry.status == "ACTIVE", BlocklistEntry.expires_at <= now).all()
    for entry in due:
        entry.status = "EXPIRED"
        db.add(AuditLog(action="BLOCKLIST_EXPIRED", actor="System", resource_type="BlocklistEntry",
                        resource_id=str(entry.id), details=f"{entry.indicator_type} {entry.value} reached its TTL."))
    if due:
        db.commit()
    return len(due)


FEEDS = {"ip": ("ip", "cidr"), "domain": ("domain",), "url": ("url",)}


def render_feed(db: Session, feed: str, strip_scheme: bool = False) -> Tuple[str, str]:
    """Returns (body, version). The version is a hash of the content, usable as an ETag."""
    types = FEEDS[feed]
    now = naive_utc_now()
    rows = db.query(BlocklistEntry.value).filter(
        BlocklistEntry.status == "ACTIVE", BlocklistEntry.indicator_type.in_(types),
        BlocklistEntry.expires_at > now,
    ).order_by(BlocklistEntry.value).all()
    values = [r[0] for r in rows]
    if feed == "url" and strip_scheme:
        values = [v.split("://", 1)[1] for v in values]
    body = f"# CYBERSHIELD AI blocklist ({feed}); {len(values)} active entries\n" + "".join(v + "\n" for v in values)
    return body, hashlib.sha256(body.encode()).hexdigest()[:32]
