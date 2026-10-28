"""Administrator-editable security configuration, stored in the database and audited on every change."""
from typing import Any, Dict, List

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import AuditLog, SecuritySetting, naive_utc_now

SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# key -> definition. Everything an administrator may change lives here, with limits, so the UI and the API agree.
DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "l1_low_risk_threshold": {
        "type": "int", "default": 35, "min": 10, "max": 60, "group": "Triage (L1)",
        "label": "Close alerts below this risk score",
        "help": "L1 closes an alert scoring below this unless the same entity has higher-risk alerts."},
    "l1_critical_threshold": {
        "type": "int", "default": 85, "min": 70, "max": 99, "group": "Triage (L1)",
        "label": "Critical severity starts at risk score",
        "help": "Alerts at or above this can never be closed by a rule."},
    "l1_duplicate_window_minutes": {
        "type": "int", "default": 15, "min": 1, "max": 120, "group": "Triage (L1)",
        "label": "Duplicate window (minutes)",
        "help": "An identical alert inside this window is treated as a duplicate."},
    "alert_min_severity": {
        "type": "choice", "default": "Medium", "choices": ["Low", "Medium", "High", "Critical"], "group": "Alerting",
        "label": "Send email alerts from severity",
        "help": "Alerts below this severity are recorded but not emailed or texted."},
    "sms_min_severity": {
        "type": "choice", "default": "High", "choices": ["Medium", "High", "Critical"], "group": "Alerting",
        "label": "Send SMS alerts from severity",
        "help": "SMS is reserved for urgent alerts."},
}


def _coerce(key: str, raw: Any) -> Any:
    d = DEFINITIONS[key]
    if d["type"] == "int":
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise HTTPException(422, f"{d['label']} must be a whole number.")
        if not d["min"] <= value <= d["max"]:
            raise HTTPException(422, f"{d['label']} must be between {d['min']} and {d['max']}.")
        return value
    if raw not in d["choices"]:
        raise HTTPException(422, f"{d['label']} must be one of {d['choices']}.")
    return raw


def get(db: Session, key: str) -> Any:
    row = db.get(SecuritySetting, key)
    if row is None:
        return DEFINITIONS[key]["default"]
    try:
        return _coerce(key, row.value)
    except HTTPException:
        return DEFINITIONS[key]["default"]


def all_settings(db: Session) -> List[Dict[str, Any]]:
    out = []
    for key, d in DEFINITIONS.items():
        row = db.get(SecuritySetting, key)
        out.append({"key": key, **{k: v for k, v in d.items() if k != "default"}, "default": d["default"],
                    "value": get(db, key), "updated_by": row.updated_by if row else None,
                    "updated_at": row.updated_at if row else None})
    return out


def update(db: Session, changes: Dict[str, Any], actor: str) -> None:
    unknown = set(changes) - set(DEFINITIONS)
    if unknown:
        raise HTTPException(422, f"Unknown setting(s): {sorted(unknown)}.")
    clean = {k: _coerce(k, v) for k, v in changes.items()}
    if clean.get("l1_low_risk_threshold", get(db, "l1_low_risk_threshold")) >= clean.get("l1_critical_threshold", get(db, "l1_critical_threshold")):
        raise HTTPException(422, "The close-below threshold must be lower than the critical threshold.")
    for key, value in clean.items():
        old = get(db, key)
        if old == value:
            continue
        row = db.get(SecuritySetting, key)
        if row is None:
            db.add(SecuritySetting(key=key, value=str(value), updated_by=actor))
        else:
            row.value, row.updated_by, row.updated_at = str(value), actor, naive_utc_now()
        db.add(AuditLog(action="SECURITY_SETTING_CHANGED", actor=actor, resource_type="SecuritySetting", resource_id=key,
                        details=f"{DEFINITIONS[key]['label']}: {old} -> {value}"))


def put_fact(db: Session, key: str, value: str) -> None:
    """Operational facts such as heartbeats; not administrator settings and not audited."""
    row = db.get(SecuritySetting, key)
    if row is None:
        db.add(SecuritySetting(key=key, value=value, updated_by="system"))
    else:
        row.value, row.updated_at = value, naive_utc_now()


def get_fact(db: Session, key: str):
    row = db.get(SecuritySetting, key)
    return (row.value, row.updated_at) if row else (None, None)
