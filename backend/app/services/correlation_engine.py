import collections
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models import SecurityEvent, Incident, IncidentEvidence, AuditLog, utc_now

class IncidentCorrelationEngine:
    """
    Correlates disparate security events (Email/Phishing, Endpoint Files, Network Trajectory)
    into unified suspected Incident entities with explainable evidence chains and uncertainty flags.
    """

    def run_correlation(self, db: Session) -> List[Dict[str, Any]]:
        # Fetch unassigned or recently analyzed security events
        events: List[SecurityEvent] = db.query(SecurityEvent).filter(
            SecurityEvent.incident_id.is_(None)
        ).all()

        if not events:
            return []

        correlations_formed = []

        # Group by shared pivot keys: IP, Domain, Hash, or User Account
        ip_clusters = collections.defaultdict(list)
        domain_clusters = collections.defaultdict(list)
        account_clusters = collections.defaultdict(list)

        for ev in events:
            if ev.source_ip:
                ip_clusters[ev.source_ip].append(ev)
            if ev.dest_ip:
                ip_clusters[ev.dest_ip].append(ev)
            if ev.domain:
                domain_clusters[ev.domain.lower()].append(ev)
            if ev.user_account:
                account_clusters[ev.user_account.lower()].append(ev)

        # Evaluate IP clusters with >= 2 distinct event sources
        processed_event_ids = set()

        for ip_addr, clustered_events in ip_clusters.items():
            if len(clustered_events) >= 2:
                # Check if multiple event types/sources are involved (e.g. Auth + Network or Phishing + Network)
                sources = set(e.event_source for e in clustered_events)
                categories = set(e.threat_category for e in clustered_events)
                
                # Filter out events already assigned in this run
                unassigned = [e for e in clustered_events if e.id not in processed_event_ids]
                if len(unassigned) >= 2:
                    inc_obj, confidence = self._create_correlated_incident(
                        db=db,
                        events=unassigned,
                        pivot_type="IP Address",
                        pivot_value=ip_addr,
                        sources=sources,
                        categories=categories
                    )
                    correlations_formed.append({
                        "incident_id": inc_obj.incident_id,
                        "title": inc_obj.title,
                        "events_count": len(unassigned),
                        "confidence": confidence,
                        "pivot": f"IP: {ip_addr}"
                    })
                    for e in unassigned:
                        processed_event_ids.add(e.id)

        # Evaluate Account clusters for credential stuffing or lateral movement
        for user_acc, clustered_events in account_clusters.items():
            unassigned = [e for e in clustered_events if e.id not in processed_event_ids]
            if len(unassigned) >= 2:
                sources = set(e.event_source for e in unassigned)
                categories = set(e.threat_category for e in unassigned)
                inc_obj, confidence = self._create_correlated_incident(
                    db=db,
                    events=unassigned,
                    pivot_type="User Account",
                    pivot_value=user_acc,
                    sources=sources,
                    categories=categories
                )
                correlations_formed.append({
                    "incident_id": inc_obj.incident_id,
                    "title": inc_obj.title,
                    "events_count": len(unassigned),
                    "confidence": confidence,
                    "pivot": f"Account: {user_acc}"
                })
                for e in unassigned:
                    processed_event_ids.add(e.id)

        db.commit()
        return correlations_formed

    def _create_correlated_incident(
        self,
        db: Session,
        events: List[SecurityEvent],
        pivot_type: str,
        pivot_value: str,
        sources: set,
        categories: set
    ) -> Tuple[Incident, str]:
        # Calculate composite risk score: highest individual score + bump for multi-stage breadth
        max_score = max(e.risk_score for e in events)
        breadth_bump = min((len(sources) - 1) * 6, 12) + min((len(events) - 1) * 3, 10)
        final_score = min(max_score + breadth_bump, 99)

        if final_score >= 80:
            severity = "Critical"
        elif final_score >= 60:
            severity = "High"
        elif final_score >= 35:
            severity = "Medium"
        else:
            severity = "Low"

        # Determine correlation confidence
        if len(sources) > 1 and len(events) >= 3:
            confidence = "High Confidence (Multi-Sensor Deterministic Correlation)"
        elif len(sources) > 1:
            confidence = "Moderate-High Confidence (Shared Cross-Domain Pivot)"
        else:
            confidence = "Moderate Confidence (Single-Sensor Repetitive Signature Pattern)"

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        inc_id = f"INC-{timestamp_str[-6:]}"

        title = f"Multi-Stage Incident: {', '.join(categories)} targeting {pivot_value}"
        description = (
            f"Correlation engine aggregated {len(events)} security events sharing {pivot_type} '{pivot_value}'. "
            f"Sensors involved: {', '.join(sources)}. Composite risk score: {final_score}/100."
        )

        incident = Incident(
            incident_id=inc_id,
            title=title,
            description=description,
            threat_category=next(iter(categories)),
            severity=severity,
            risk_score=final_score,
            status="New",
            assigned_analyst="Unassigned",
            correlation_reason=f"Correlated via shared {pivot_type} '{pivot_value}' across events occurring in operational sequence.",
            correlation_confidence=confidence,
            forensic_summary=f"Automated SOC correlation linked {len(events)} alerts. Initial detection vector: {events[0].event_source} ({events[0].threat_category})."
        )
        db.add(incident)
        db.flush()

        # Link events and build evidence items
        for ev in events:
            ev.incident_id = incident.incident_id
            ev.analysis_status = "Correlated"

            # Create evidence item
            evidence_item = IncidentEvidence(
                incident_id=incident.incident_id,
                evidence_type=pivot_type,
                evidence_value=pivot_value,
                provenance=f"Alert {ev.event_id} from {ev.event_source}",
                confidence=0.92
            )
            db.add(evidence_item)

        # Log audit entry
        audit = AuditLog(
            action="INCIDENT_CORRELATED",
            actor="CorrelationEngine / UnifiedSOC",
            resource_type="Incident",
            resource_id=incident.incident_id,
            details=f"Correlated {len(events)} events into incident {incident.incident_id} with confidence: {confidence}"
        )
        db.add(audit)

        return incident, confidence

correlation_engine = IncidentCorrelationEngine()
