from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db, get_db_status
from app.models import SecurityEvent, Incident, ThreatAnalysis, SecretFinding, Employee, AuditLog, IngestState
from app.schemas import DashboardMetrics, ThreatSeverityDistribution, ActivityDataPoint, SecurityEventResponse, CategoryCount
from app.config import settings

router = APIRouter(prefix="/dashboard", tags=["Dashboard Analytics"])

PHISHING_LIKE = ("%phish%", "%credential harvest%")
NETWORK_LIKE = ("%network%", "%scan%", "%recon%", "%brute%", "%exfil%", "%c2%", "%traffic%", "%compromise%")


def _like_any(column, patterns):
    cond = None
    for p in patterns:
        c = column.ilike(p)
        cond = c if cond is None else (cond | c)
    return cond


def _naive_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@router.get("/metrics", response_model=DashboardMetrics)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    now = _naive_now()
    day_ago, two_days_ago = now - timedelta(hours=24), now - timedelta(hours=48)
    total_events = db.query(SecurityEvent).count()
    threats = db.query(SecurityEvent).filter(SecurityEvent.risk_score >= 35).count()
    critical_inc = db.query(Incident).filter(Incident.severity == "Critical").count()
    high_inc = db.query(Incident).filter(Incident.severity == "High").count()
    phishing_scans = db.query(ThreatAnalysis).filter(ThreatAnalysis.analysis_type.in_(["url", "email", "sms"])).count()
    network_anomalies = db.query(SecurityEvent).filter(_like_any(SecurityEvent.threat_category, NETWORK_LIKE)).count()
    open_investigations = db.query(Incident).filter(Incident.status.in_(["New", "Investigating"])).count()
    secret_leaks = db.query(SecretFinding).filter(SecretFinding.status.in_(["NEW", "CONTAINED"])).count()
    active_employees = db.query(Employee).filter(Employee.is_active == True).count()  # noqa: E712
    suspicious_urls = db.query(ThreatAnalysis).filter(
        ThreatAnalysis.analysis_type == "url", ThreatAnalysis.risk_score >= 35).count()
    last_24 = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= day_ago).count()
    prev_24 = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= two_days_ago, SecurityEvent.timestamp < day_ago).count()
    critical_24 = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= day_ago, SecurityEvent.severity == "Critical").count()

    return DashboardMetrics(
        total_events_analyzed=total_events,
        threats_detected=threats,
        critical_incidents=critical_inc,
        high_incidents=high_inc,
        phishing_scans_total=phishing_scans,
        network_anomalies_total=network_anomalies,
        secret_leaks_total=secret_leaks,
        active_employees_monitored=active_employees,
        open_investigations=open_investigations,
        system_status="Operational",
        db_mode=get_db_status()["provider"],
        # No reputation client exists: a configured key must never read as a live connection.
        reputation_service_status="Not connected: no external reputation lookups are made",
        ml_models_active=True,
        events_last_24h=last_24,
        events_prev_24h=prev_24,
        critical_events_last_24h=critical_24,
        suspicious_urls_total=suspicious_urls,
        zetaris_connected_sources=db.query(IngestState).filter(IngestState.last_status == "OK").count(),
        simulated_events_total=db.query(SecurityEvent).filter(SecurityEvent.is_simulated.is_(True)).count(),
    )


@router.get("/critical-alerts", response_model=List[SecurityEventResponse])
def get_critical_alerts(limit: int = Query(15, ge=1, le=50), db: Session = Depends(get_db)):
    """High and Critical alerts still open (not closed by L1 or a person), newest first, unacknowledged ahead of acknowledged."""
    return (db.query(SecurityEvent)
            .filter(SecurityEvent.severity.in_(("Critical", "High")), SecurityEvent.analysis_status != "Closed")
            .order_by(SecurityEvent.is_acknowledged.asc(), SecurityEvent.timestamp.desc()).limit(limit).all())


@router.get("/severity-distribution", response_model=ThreatSeverityDistribution)
def get_severity_distribution(db: Session = Depends(get_db)):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    results = db.query(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity).all()
    for sev, count in results:
        if sev in counts:
            counts[sev] = count
    return ThreatSeverityDistribution(
        critical=counts["Critical"], high=counts["High"], medium=counts["Medium"], low=counts["Low"])


@router.get("/category-distribution", response_model=List[CategoryCount])
def get_category_distribution(limit: int = Query(6, ge=1, le=12), db: Session = Depends(get_db)):
    rows = (db.query(SecurityEvent.threat_category, func.count(SecurityEvent.id))
            .group_by(SecurityEvent.threat_category).order_by(func.count(SecurityEvent.id).desc()).all())
    top = [CategoryCount(category=c, count=n) for c, n in rows[:limit]]
    rest = sum(n for _, n in rows[limit:])
    if rest:
        top.append(CategoryCount(category="Other", count=rest))
    return top


@router.get("/activity-timeline", response_model=List[ActivityDataPoint])
def get_activity_timeline(db: Session = Depends(get_db)):
    """Seven 4-hour buckets ending now. Counts are exactly what is in the database: empty periods read zero."""
    now = _naive_now()
    points = []
    for i in range(6, -1, -1):
        end = now - timedelta(hours=i * 4)
        start = end - timedelta(hours=4)
        in_bucket = (SecurityEvent.timestamp > start) & (SecurityEvent.timestamp <= end)
        points.append(ActivityDataPoint(
            time_label=end.strftime("%b %d %H:%M"),
            bucket_end=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            total_events=db.query(SecurityEvent).filter(in_bucket).count(),
            threats=db.query(SecurityEvent).filter(in_bucket, SecurityEvent.risk_score >= 50).count(),
            phishing=db.query(SecurityEvent).filter(in_bucket, _like_any(SecurityEvent.threat_category, PHISHING_LIKE)).count(),
            network=db.query(SecurityEvent).filter(in_bucket, _like_any(SecurityEvent.threat_category, NETWORK_LIKE)).count(),
        ))
    return points

@router.get("/recent-events", response_model=List[SecurityEventResponse])
def get_recent_events(
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(15, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if severity and severity != "All":
        query = query.filter(SecurityEvent.severity == severity)
    if search:
        s = f"%{search}%"
        query = query.filter(
            SecurityEvent.event_id.ilike(s) |
            SecurityEvent.threat_category.ilike(s) |
            SecurityEvent.event_source.ilike(s) |
            SecurityEvent.evidence.ilike(s) |
            SecurityEvent.source_ip.ilike(s) |
            SecurityEvent.user_account.ilike(s)
        )
    events = query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()
    return events
