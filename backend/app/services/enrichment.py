"""Adds reputation-service findings to detector results. The detectors stay local and deterministic; this layer is optional."""
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.config import settings
from app.schemas import FileAnalysisResponse, IndicatorDetail, PhishingAnalysisResponse
from app.services import threat_intel as ti
from app.services import url_features as uf


def _category(score: int) -> str:
    return "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"


def _summaries(intel: Dict[str, Any]) -> str:
    return " ".join(r.get("summary", "") for r in intel["results"] if r.get("status") in ("ok", "not_found", "error") and r.get("summary"))


def _status_line(intel: Dict[str, Any]) -> str:
    asked = [r for r in intel["results"] if r.get("status") in ("ok", "not_found")]
    return ("Reputation checked: " + ", ".join(sorted({r["provider"] for r in asked}))) if asked else \
        "No reputation service answered (none configured, rate-limited or unreachable)"


def enrich_url(db: Session, result: PhishingAnalysisResponse) -> PhishingAnalysisResponse:
    host = uf.ParsedUrl(result.target).hostname
    if not (ti.configured(ti.VT) or ti.configured(ti.ABUSE)) or not host:
        return result
    parsed = uf.ParsedUrl(result.target)
    if parsed.is_internal or (parsed.registrable in uf.popular_domains() and not parsed.on_user_content_host):
        return result                                       # nothing to learn and no reason to spend quota
    intel = ti.lookup(db, parsed.hostname if parsed.is_ip else result.target)
    result.reputation_status = _status_line(intel)
    if intel["malicious"]:
        result.risk_score = max(result.risk_score, 90)
        result.indicators.append(IndicatorDetail(category="Threat Intelligence", signal="Known malicious", weight=40, severity="Critical",
                                                 description=_summaries(intel)))
    elif intel["suspicious"]:
        result.risk_score = min(99, result.risk_score + 25)
        result.indicators.append(IndicatorDetail(category="Threat Intelligence", signal="Reported as suspicious", weight=25, severity="High",
                                                 description=_summaries(intel)))
    elif any(r.get("status") in ("ok", "not_found") for r in intel["results"]):
        result.indicators.append(IndicatorDetail(category="Threat Intelligence", signal="No reports found", weight=0, severity="Low",
                                                 description=_summaries(intel) + " A clean reputation does not clear a new phishing page."))
    result.risk_category = _category(result.risk_score)
    return result


def enrich_file(db: Session, result: FileAnalysisResponse) -> FileAnalysisResponse:
    if not ti.configured(ti.VT):
        return result
    intel = ti.lookup(db, result.sha256)
    row = next((r for r in intel["results"] if r["provider"] == ti.VT), None) or {}
    result.reputation_lookup.update({"service": result.reputation_lookup.get("service", "") + " + VirusTotal",
                                     "virustotal_status": row.get("status"), "virustotal_summary": row.get("summary")})
    if row.get("verdict") == "malicious":
        result.risk_score = max(result.risk_score, 90)
        result.suspicious_patterns.append(f"VirusTotal: {row.get('summary')}")
        result.reputation_lookup["match_found"] = True
    elif row.get("verdict") == "suspicious":
        result.risk_score = min(99, result.risk_score + 25)
        result.suspicious_patterns.append(f"VirusTotal: {row.get('summary')}")
    result.risk_category = _category(result.risk_score)
    if row.get("status") == "not_found":
        result.reputation_lookup["notice"] = "VirusTotal has not seen this file; that is common for new or private files and does not mean it is safe."
    return result


def evidence_for_ips(db: Session, ips, limit: int = 3) -> Dict[str, Any]:
    """Used by L2: reputation for the first few external addresses of an incident."""
    if not (ti.configured(ti.VT) or ti.configured(ti.ABUSE)):
        return {"available": False, "reason": "No reputation service is configured."}
    results, bonus = [], False
    for ip in list(ips)[:limit]:
        intel = ti.lookup(db, ip)
        if intel["type"] != "ip":
            continue
        results.append({"ip": ip, "malicious": intel["malicious"], "suspicious": intel["suspicious"],
                        "summary": _summaries(intel) or "No provider answered."})
        bonus = bonus or intel["malicious"]
    return {"available": True, "results": results, "known_bad": bonus,
            "any_answered": any(r["summary"] != "No provider answered." for r in results)}
