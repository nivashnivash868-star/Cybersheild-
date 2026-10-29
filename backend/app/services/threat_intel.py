"""Reputation lookups against VirusTotal (v3) and AbuseIPDB (v2).

What is sent: public IP addresses, public domains and file hashes. Never file contents, never private addresses or
internal hostnames, and never a full URL unless TI_SEND_FULL_URLS is on (a URL can carry tokens). Answers are cached
(TI_CACHE_HOURS), calls are rate-limited to the provider's free-tier quotas, and a provider is described as connected
only after a call to it really succeeded.
"""
import base64
import ipaddress
import json
import logging
import re
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ThreatIntelRecord, naive_utc_now
from app.services import settings_store
from app.utils.ratelimit import limiter

logger = logging.getLogger("cybershield.threat_intel")

VT = "virustotal"
ABUSE = "abuseipdb"
_transport: Optional[httpx.BaseTransport] = None      # tests inject a fake provider here
_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".intranet", ".home", ".localdomain", ".test", ".example", ".invalid", ".localhost")


def configured(provider: str) -> bool:
    return bool({VT: settings.VIRUSTOTAL_API_KEY, ABUSE: settings.ABUSEIPDB_API_KEY}[provider]) and settings.TI_LOOKUPS_ENABLED


def classify(indicator: str) -> Tuple[str, str]:
    """(type, normalised value). type is ip | domain | hash | url | invalid | internal."""
    value = (indicator or "").strip()
    if not value or len(value) > 2000:
        return "invalid", value
    if _HASH.match(value):
        return "hash", value.lower()
    try:
        ip = ipaddress.ip_address(value)
        return ("ip", str(ip)) if ip.is_global else ("internal", str(ip))
    except ValueError:
        pass
    if "://" in value or "/" in value:
        from app.services.url_features import ParsedUrl
        parsed = ParsedUrl(value)
        host = parsed.hostname
        if not host or parsed.is_internal:
            return "internal", value
        return "url", value
    host = value.lower().rstrip(".")
    if _DOMAIN.match(host) and not host.endswith(_INTERNAL_SUFFIXES):
        return "domain", host
    single_label = re.fullmatch(r"[a-z0-9-]+", host) is not None
    return ("internal" if single_label or host.endswith(_INTERNAL_SUFFIXES) else "invalid"), value


def _providers_for(kind: str) -> List[str]:
    return {"ip": [ABUSE, VT], "domain": [VT], "hash": [VT], "url": [VT]}.get(kind, [])


# ------------------------------------------------------------------------------------------- providers

def _client() -> httpx.Client:
    return httpx.Client(timeout=10, transport=_transport, follow_redirects=False)


def _abuse(indicator: str) -> Dict[str, Any]:
    with _client() as c:
        r = c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": indicator, "maxAgeInDays": 90},
                  headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"})
    if r.status_code == 429:
        raise _RateLimited()
    if r.status_code in (401, 403):
        raise _BadKey("AbuseIPDB rejected the API key.")
    r.raise_for_status()
    d = r.json()["data"]
    score, reports = int(d.get("abuseConfidenceScore", 0)), int(d.get("totalReports", 0))
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else ("clean" if reports == 0 else "unknown")
    return {"verdict": verdict, "score": score,
            "summary": f"AbuseIPDB confidence of abuse {score}% from {reports} report(s) in 90 days"
                       + (f"; {d.get('isp')}" if d.get("isp") else "") + (f", {d.get('countryCode')}" if d.get("countryCode") else "") + ".",
            "detail": {"reports": reports, "country": d.get("countryCode"), "isp": d.get("isp"), "usage": d.get("usageType"),
                       "last_reported": d.get("lastReportedAt"), "whitelisted": d.get("isWhitelisted")}}


def _vt_path(kind: str, indicator: str) -> str:
    if kind == "ip":
        return f"ip_addresses/{indicator}"
    if kind == "domain":
        return f"domains/{indicator}"
    if kind == "hash":
        return f"files/{indicator}"
    return "urls/" + base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")


def _vt(kind: str, indicator: str) -> Optional[Dict[str, Any]]:
    with _client() as c:
        r = c.get(f"https://www.virustotal.com/api/v3/{_vt_path(kind, indicator)}", headers={"x-apikey": settings.VIRUSTOTAL_API_KEY})
    if r.status_code == 404:
        return None
    if r.status_code == 429:
        raise _RateLimited()
    if r.status_code in (401, 403):
        raise _BadKey("VirusTotal rejected the API key.")
    r.raise_for_status()
    attrs = r.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    verdict = "malicious" if mal >= 5 else "suspicious" if mal >= 1 or sus >= 3 else ("clean" if total else "unknown")
    name = attrs.get("meaningful_name") or (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return {"verdict": verdict, "score": mal,
            "summary": f"VirusTotal: {mal} of {total} engines flag it malicious" + (f", {sus} suspicious" if sus else "")
                       + (f" ({name})" if name else "") + ("." if total else "; no analysis available."),
            "detail": {"malicious": mal, "suspicious": sus, "harmless": int(stats.get("harmless", 0)),
                       "undetected": int(stats.get("undetected", 0)), "reputation": attrs.get("reputation"), "threat": name}}


class _RateLimited(Exception):
    pass


class _BadKey(Exception):
    pass


def _within_quota(provider: str) -> bool:
    if provider == VT:
        return limiter.hit("ti:vt:min", settings.TI_VT_PER_MINUTE, 60) and limiter.hit("ti:vt:day", settings.TI_VT_PER_DAY, 86400)
    return limiter.hit("ti:abuse:day", settings.TI_ABUSEIPDB_PER_DAY, 86400)


def _remember(db: Session, provider: str, ok: bool, message: str) -> None:
    settings_store.put_fact(db, f"ti_{provider}_{'ok' if ok else 'error'}", f"{naive_utc_now().isoformat()}|{message[:200]}")


# ------------------------------------------------------------------------------------------- public API

def lookup(db: Session, indicator: str, *, force: bool = False) -> Dict[str, Any]:
    """Reputation for one indicator from every provider that applies. Never raises: failures are reported per provider."""
    kind, value = classify(indicator)
    out: Dict[str, Any] = {"indicator": indicator.strip()[:255], "type": kind, "results": [], "malicious": False, "suspicious": False}
    if kind in ("internal", "invalid"):
        out["note"] = ("Internal or non-public addresses are never sent to a reputation service."
                       if kind == "internal" else "That is not an IP address, domain, file hash or URL.")
        return out
    target = value
    if kind == "url" and not settings.TI_SEND_FULL_URLS:
        from app.services.url_features import ParsedUrl
        target, kind = ParsedUrl(value).hostname, "domain"
        out["note"] = "Only the domain of the URL was looked up (TI_SEND_FULL_URLS is off)."
        if classify(target)[0] != "domain":
            out["type"], out["results"] = kind, [{"provider": VT, "status": "skipped", "summary": "Not a public domain name."}]
            return out
    ttl = timedelta(hours=settings.TI_CACHE_HOURS)
    for provider in _providers_for(kind):
        row: Dict[str, Any] = {"provider": provider}
        if not configured(provider):
            row.update(status="not_configured", summary=f"{'VirusTotal' if provider == VT else 'AbuseIPDB'} is not configured.")
            out["results"].append(row)
            continue
        cached = db.query(ThreatIntelRecord).filter(ThreatIntelRecord.indicator == target, ThreatIntelRecord.provider == provider) \
            .order_by(ThreatIntelRecord.fetched_at.desc()).first()
        age_limit = timedelta(minutes=10) if cached and cached.status == "error" else ttl
        if cached and not force and naive_utc_now() - cached.fetched_at < age_limit:
            row.update(json.loads(cached.result_json), status=cached.status, cached=True, fetched_at=cached.fetched_at.isoformat() + "Z")
        elif not _within_quota(provider):
            row.update(status="rate_limited", summary="Skipped: the provider's quota for this period is used up.")
        else:
            try:
                data = _abuse(target) if provider == ABUSE else _vt(kind, target)
                status, payload = ("ok", data) if data else ("not_found", {"verdict": "unknown", "summary": "VirusTotal has not seen this indicator."})
                _remember(db, provider, True, f"{kind} lookup")
            except _RateLimited:
                status, payload = "error", {"verdict": "unknown", "summary": "The provider answered 'too many requests'."}
                _remember(db, provider, False, "rate limited by provider")
            except _BadKey as exc:
                status, payload = "error", {"verdict": "unknown", "summary": str(exc)}
                _remember(db, provider, False, str(exc))
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                status, payload = "error", {"verdict": "unknown", "summary": f"Lookup failed ({type(exc).__name__})."}
                _remember(db, provider, False, f"{type(exc).__name__}")
            db.query(ThreatIntelRecord).filter(ThreatIntelRecord.indicator == target, ThreatIntelRecord.provider == provider).delete(synchronize_session=False)
            db.add(ThreatIntelRecord(indicator=target, provider=provider, status=status, result_json=json.dumps(payload)))
            db.flush()
            row.update(payload, status=status, cached=False)
        out["results"].append(row)
    out["malicious"] = any(r.get("verdict") == "malicious" for r in out["results"])
    out["suspicious"] = out["malicious"] or any(r.get("verdict") == "suspicious" for r in out["results"])
    return out


def provider_status(db: Session) -> List[Dict[str, Any]]:
    """Honest status per provider: 'connected' only if the last call succeeded."""
    rows = []
    for provider, label in ((VT, "VirusTotal"), (ABUSE, "AbuseIPDB")):
        ok_val, _ = settings_store.get_fact(db, f"ti_{provider}_ok")
        err_val, _ = settings_store.get_fact(db, f"ti_{provider}_error")
        ok_at = ok_val.split("|", 1)[0] if ok_val else None
        err_at, err_msg = (err_val.split("|", 1) + [""])[:2] if err_val else (None, "")
        key_set = bool({VT: settings.VIRUSTOTAL_API_KEY, ABUSE: settings.ABUSEIPDB_API_KEY}[provider])
        if not key_set:
            state, detail = "not_configured", "API key not set."
        elif not settings.TI_LOOKUPS_ENABLED:
            state, detail = "disabled", "Lookups are turned off (TI_LOOKUPS_ENABLED)."
        elif ok_at and (not err_at or ok_at >= err_at):
            state, detail = "connected", f"Last successful lookup {ok_at} UTC."
        elif err_at:
            state, detail = "error", f"Last lookup failed at {err_at} UTC: {err_msg}"
        else:
            state, detail = "unverified", "Key is set but no lookup has been made yet. Use Test to verify it."
        rows.append({"provider": provider, "name": label, "state": state, "detail": detail})
    return rows


def test_provider(db: Session, provider: str) -> Dict[str, Any]:
    """A real call with a harmless public indicator, so 'connected' means something."""
    sample = {"abuseipdb": "1.1.1.1", "virustotal": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}[provider]
    result = lookup(db, sample, force=True)
    row = next((r for r in result["results"] if r["provider"] == provider), {"status": "not_configured", "summary": "Not configured."})
    return {"provider": provider, "ok": row["status"] in ("ok", "not_found"), "status": row["status"], "detail": row.get("summary", "")}
