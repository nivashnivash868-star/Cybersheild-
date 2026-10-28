from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models import (
    User, Employee, MonitoringSource, SecretFinding, NotificationDelivery,
    SecurityEvent, ThreatAnalysis, Incident, IncidentEvidence,
    InvestigationNote, ResponseAction, AuditLog, utc_now,
    UserSession, PasswordResetToken, BlocklistEntry, FeedToken
)
from app.config import settings
from app.utils.auth import get_password_hash

def seed_demo_soc_data(db: Session, force_reset: bool = False):
    """
    Populates realistic, enterprise-grade cybersecurity data including:
    - 4 RBAC role users (Super Admin, Security Administrator, SOC Analyst, Employee)
    - Corporate employee directory with monitoring policies
    - 24/7 monitoring sources (Email, Endpoint, DNS, Firewall, Zeek, IdP, CloudTrail)
    - Company secret detection / DLP findings (masked in UI)
    - Automated notification deliveries and audit trail
    - Multi-stage incidents and security events
    """
    if not settings.DEMO_MODE:
        return {"status": "disabled", "message": "Demo data is off (DEMO_MODE is not set)."}

    user_count = db.query(User).count()
    if user_count > 0 and not force_reset:
        return {"status": "skipped", "message": f"Database already contains {user_count} users."}

    if force_reset:
        db.query(AuditLog).delete()
        db.query(UserSession).delete()
        db.query(PasswordResetToken).delete()
        db.query(BlocklistEntry).delete()
        db.query(FeedToken).delete()
        db.query(NotificationDelivery).delete()
        db.query(SecretFinding).delete()
        db.query(ResponseAction).delete()
        db.query(InvestigationNote).delete()
        db.query(IncidentEvidence).delete()
        db.query(SecurityEvent).delete()
        db.query(ThreatAnalysis).delete()
        db.query(Incident).delete()
        db.query(MonitoringSource).delete()
        db.query(Employee).delete()
        db.query(User).delete()
        db.commit()

    now = datetime.now(timezone.utc)
    default_password_hash = get_password_hash("CyberShield@2026!")

    # --- 1. RBAC Users (Super Admin, SecAdmin, SOC Analyst, Employee) ---
    users = [
        User(
            email="admin@cybershield.corp",
            hashed_password=default_password_hash,
            full_name="Chief Information Security Officer (CISO)",
            role="Super Admin",
            is_active=True,
            department="Executive Security Office",
            employee_id="EMP-0001",
            created_at=now - timedelta(days=90),
            last_login=now - timedelta(minutes=10)
        ),
        User(
            email="secadmin@cybershield.corp",
            hashed_password=default_password_hash,
            full_name="David Vance",
            role="Security Administrator",
            is_active=True,
            department="SecOps & Identity Management",
            employee_id="EMP-0002",
            created_at=now - timedelta(days=60),
            last_login=now - timedelta(minutes=45)
        ),
        User(
            email="analyst@cybershield.corp",
            hashed_password=default_password_hash,
            full_name="Sarah Chen",
            role="SOC Analyst",
            is_active=True,
            department="Incident Response Team",
            employee_id="EMP-0003",
            created_at=now - timedelta(days=45),
            last_login=now - timedelta(minutes=5)
        ),
        User(
            email="alex.turner@enterprise-corp.com",
            hashed_password=default_password_hash,
            full_name="Alex Turner",
            role="Employee",
            is_active=True,
            department="Finance & Procurement",
            employee_id="EMP-1042",
            created_at=now - timedelta(days=30),
            last_login=now - timedelta(hours=2)
        )
    ]
    db.add_all(users)
    db.flush()

    # --- 2. Corporate Employees Directory ---
    employees = [
        Employee(
            employee_id="EMP-1042",
            full_name="Alex Turner",
            company_email="alex.turner@enterprise-corp.com",
            phone_number="+1 (555) 234-5678",
            department="Finance",
            role_title="Senior Financial Analyst",
            monitoring_policy="Executive High-Risk",
            is_active=True,
            risk_score=78,
            created_at=now - timedelta(days=30)
        ),
        Employee(
            employee_id="EMP-1043",
            full_name="Robert Simmons",
            company_email="r.simmons@enterprise-corp.com",
            phone_number="+1 (555) 345-6789",
            department="Accounting",
            role_title="Accounts Payable Controller",
            monitoring_policy="Standard Workstation",
            is_active=True,
            risk_score=85,
            created_at=now - timedelta(days=45)
        ),
        Employee(
            employee_id="EMP-1044",
            full_name="Elena Rostova",
            company_email="elena.r@enterprise-corp.com",
            phone_number="+1 (555) 456-7890",
            department="DevOps & Cloud",
            role_title="Principal Cloud Architect",
            monitoring_policy="DevOps & Cloud Admin",
            is_active=True,
            risk_score=65,
            created_at=now - timedelta(days=60)
        ),
        Employee(
            employee_id="EMP-1045",
            full_name="Marcus Thorne",
            company_email="m.thorne@enterprise-corp.com",
            phone_number="+1 (555) 567-8901",
            department="Engineering",
            role_title="Senior Backend Systems Engineer",
            monitoring_policy="Standard Workstation",
            is_active=True,
            risk_score=15,
            created_at=now - timedelta(days=90)
        ),
        Employee(
            employee_id="EMP-1046",
            full_name="Priya Patel",
            company_email="priya.p@enterprise-corp.com",
            phone_number="+1 (555) 678-9012",
            department="Human Resources",
            role_title="Head of People Operations",
            monitoring_policy="Standard Workstation",
            is_active=True,
            risk_score=10,
            created_at=now - timedelta(days=120)
        ),
        Employee(
            employee_id="EMP-1047",
            full_name="Johnathan Drake",
            company_email="j.drake@partner-audit.corp",
            phone_number="+1 (555) 789-0123",
            department="External Audit",
            role_title="Contract Security Auditor",
            monitoring_policy="Contractor Strict",
            is_active=True,
            risk_score=20,
            created_at=now - timedelta(days=15)
        )
    ]
    db.add_all(employees)
    db.flush()

    # --- 3. 24/7 Security Monitoring Sources ---
    sources = [
        MonitoringSource(
            source_id="SRC-M365-EMAIL",
            name="Microsoft 365 Exchange Security Ingress",
            source_type="Email Gateway",
            status="ACTIVE",
            events_ingested_count=18420,
            last_heartbeat=now - timedelta(seconds=12),
            is_simulated=True,
            configuration_json='{"retention_days": 90, "spf_dkim_check": true, "phishing_filter": "strict"}'
        ),
        MonitoringSource(
            source_id="SRC-CRWD-EDR",
            name="CrowdStrike Falcon Fleet EDR Sensor",
            source_type="Endpoint EDR",
            status="ACTIVE",
            events_ingested_count=42190,
            last_heartbeat=now - timedelta(seconds=8),
            is_simulated=True,
            configuration_json='{"hosts_monitored": 482, "tamper_protection": true, "kernel_hook": true}'
        ),
        MonitoringSource(
            source_id="SRC-CISCO-DNS",
            name="Cisco Umbrella Enterprise DNS Resolvers",
            source_type="Corporate DNS",
            status="ACTIVE",
            events_ingested_count=129400,
            last_heartbeat=now - timedelta(seconds=15),
            is_simulated=True,
            configuration_json='{"sinkholing": true, "doh_blocking": true}'
        ),
        MonitoringSource(
            source_id="SRC-PALO-NGFW",
            name="Palo Alto PA-5200 Perimeter NGFW",
            source_type="Perimeter Firewall",
            status="ACTIVE",
            events_ingested_count=87120,
            last_heartbeat=now - timedelta(seconds=5),
            is_simulated=True,
            configuration_json='{"ssl_decryption": true, "ips_active": true}'
        ),
        MonitoringSource(
            source_id="SRC-ZEEK-NIDS",
            name="Zeek Network Sensor Array (Core DMZ)",
            source_type="Network Sensor",
            status="ACTIVE",
            events_ingested_count=65300,
            last_heartbeat=now - timedelta(seconds=20),
            is_simulated=True,
            configuration_json='{"pcap_ring_gb": 500, "bpf_filter": "default"}'
        ),
        MonitoringSource(
            source_id="SRC-AZURE-IDP",
            name="Microsoft Entra ID / Okta Auth Audits",
            source_type="Identity Provider",
            status="ACTIVE",
            events_ingested_count=9850,
            last_heartbeat=now - timedelta(seconds=30),
            is_simulated=True,
            configuration_json='{"conditional_access": true, "fido2_mfa": true}'
        ),
        MonitoringSource(
            source_id="SRC-AWS-TRAIL",
            name="AWS CloudTrail Management Audit Stream",
            source_type="Cloud Audit Logs",
            status="ACTIVE",
            events_ingested_count=31240,
            last_heartbeat=now - timedelta(seconds=45),
            is_simulated=True,
            configuration_json='{"regions": ["us-east-1", "us-west-2", "eu-central-1"], "kms_encrypted": true}'
        )
    ]
    db.add_all(sources)
    db.flush()

    # --- 4. Company Secret Detection / DLP Findings ---
    secrets = [
        SecretFinding(
            finding_id="DLP-AWS-9102",
            secret_type="AWS Access Key ID",
            masked_value="AKIA****************5K2A",
            secret_hash="6dcd4ce23d88e2ee9568ba546c007c63d9131c1b",
            source_location="Git push diff on enterprise-repo/payment-service",
            employee_id="EMP-1044",
            employee_email="elena.r@enterprise-corp.com",
            severity="Critical",
            risk_score=95,
            status="NEW",
            recommendations="Revoke IAM key in AWS console and audit CloudTrail for unauthorized sts:AssumeRole actions.",
            detected_at=now - timedelta(hours=2, minutes=10)
        ),
        SecretFinding(
            finding_id="DLP-STRIPE-8819",
            secret_type="Stripe Live Secret Key",
            masked_value="sk_live_********************1234",
            secret_hash="a1b2c3d4e5f67890123456789abcdef012345678",
            source_location="Outbound draft email attachment (Q3_Stripe_Reconciliation.csv)",
            employee_id="EMP-1042",
            employee_email="alex.turner@enterprise-corp.com",
            severity="Critical",
            risk_score=92,
            status="CONTAINED",
            recommendations="Roll Stripe live secret key in dashboard. Invalidate active payment webhook secrets.",
            detected_at=now - timedelta(hours=4, minutes=30)
        ),
        SecretFinding(
            finding_id="DLP-PG-7712",
            secret_type="Database Connection URI with Password",
            masked_value="postgres://db_user:********@10.0.1.4:5432/corp_financials",
            secret_hash="f0e1d2c3b4a5968778695a4b3c2d1e0f12345678",
            source_location="Public Pastebin telemetry scrape match for company domain",
            employee_id="EMP-1043",
            employee_email="r.simmons@enterprise-corp.com",
            severity="High",
            risk_score=88,
            status="NEW",
            recommendations="Rotate database user credentials and restrict firewall listener to internal subnets only.",
            detected_at=now - timedelta(hours=6, minutes=15)
        )
    ]
    db.add_all(secrets)
    db.flush()

    # --- 5. Automated Notification Deliveries ---
    notifications = [
        NotificationDelivery(
            delivery_id="NOTIF-SOC-00101",
            recipient_type="SOC_ANALYST",
            recipient_address="soc-tier1-alerts@cybershield.corp",
            channel="EMAIL",
            severity="Critical",
            title="[CYBERSHIELD CRITICAL] Staged C2 Egress Detected for FINANCE-WS-04",
            body_preview="Suricata NIDS detected periodic 60s HTTPS beaconing to 185.220.101.45. Workstation finance asset isolated.",
            delivery_status="SENT",
            retry_count=0,
            incident_id="INC-2026-0042",
            event_id="SEC-2026-00103",
            dedup_key="dedup_beacon_185220",
            sent_at=now - timedelta(hours=2, minutes=49)
        ),
        NotificationDelivery(
            delivery_id="NOTIF-EMP-00102",
            recipient_type="EMPLOYEE",
            recipient_address="alex.turner@enterprise-corp.com",
            channel="EMAIL",
            severity="High",
            title="Security Advisory: Malicious Link Warning",
            body_preview="Notice for alex.turner@enterprise-corp.com: A link targeting Microsoft 365 credentials in your inbound queue was intercepted and blocked.",
            delivery_status="SENT",
            retry_count=0,
            incident_id="INC-2026-0042",
            event_id="SEC-2026-00101",
            dedup_key="dedup_phish_alex",
            sent_at=now - timedelta(hours=3, minutes=44)
        ),
        NotificationDelivery(
            delivery_id="NOTIF-SMS-00103",
            recipient_type="EMPLOYEE",
            recipient_address="+1 (555) 234-5678",
            channel="SMS",
            severity="High",
            title="CYBERSHIELD Security Advisory",
            body_preview="CYBERSHIELD Alert: Suspicious email intercepted. Please verify your portal advisories.",
            delivery_status="SENT",
            retry_count=0,
            incident_id="INC-2026-0042",
            dedup_key="dedup_sms_alex",
            sent_at=now - timedelta(hours=3, minutes=43)
        )
    ]
    db.add_all(notifications)
    db.flush()

    # --- 6. Incidents & Security Events ---
    inc1 = Incident(
        incident_id="INC-2026-0042",
        title="Multi-Stage Phishing with Staged C2 Egress Beaconing",
        description="Correlated multi-sensor attack vector. Began with spear-phishing credential theft email, followed by endpoint macro payload execution and recurring HTTPS C2 beaconing to rogue foreign hosting subnet.",
        threat_category="Advanced Persistent Threat (APT)",
        severity="Critical",
        risk_score=94,
        status="Investigating",
        assigned_analyst="Sarah Chen (Lead SOC Investigator)",
        assigned_employee_id="EMP-1043",
        is_escalated=True,
        created_at=now - timedelta(hours=3, minutes=45),
        updated_at=now - timedelta(minutes=15),
        correlation_reason="Correlated via shared attacker IP 185.220.101.45 and compromised workstation asset 'FINANCE-WS-04' within a 45-minute operational timeline.",
        correlation_confidence="High Confidence (Deterministic Multi-Sensor Correlation)",
        forensic_summary="Inbound phishing email delivered spoofed link to 185.220.101.45. User workstation downloaded payload 'invoice_march_q1.scr'. Network sensor recorded repeated 60-second periodic beaconing on port 443."
    )
    db.add(inc1)
    db.flush()

    # Evidence for Incident 1
    evidence_1 = [
        IncidentEvidence(
            incident_id=inc1.incident_id,
            evidence_type="C2 IP Address",
            evidence_value="185.220.101.45",
            provenance="Suricata NIDS Flow Sensor (Perimeter Egress)",
            confidence=0.98,
            captured_at=now - timedelta(hours=3, minutes=30)
        ),
        IncidentEvidence(
            incident_id=inc1.incident_id,
            evidence_type="Phishing Domain",
            evidence_value="login-microsoft365-verify.xyz",
            provenance="Proofpoint Mail Gateway Telemetry",
            confidence=0.96,
            captured_at=now - timedelta(hours=3, minutes=45)
        ),
        IncidentEvidence(
            incident_id=inc1.incident_id,
            evidence_type="SHA-256 Payload Hash",
            evidence_value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            provenance="CrowdStrike Falcon EDR Sensor (FINANCE-WS-04)",
            confidence=0.99,
            captured_at=now - timedelta(hours=3, minutes=15)
        ),
        IncidentEvidence(
            incident_id=inc1.incident_id,
            evidence_type="Target Workstation",
            evidence_value="FINANCE-WS-04 (IP: 10.0.12.84)",
            provenance="Active Directory DHCP & Kerberos Audit Logs",
            confidence=1.0,
            captured_at=now - timedelta(hours=3, minutes=10)
        ),
    ]
    for ev in evidence_1:
        db.add(ev)

    # Notes for Incident 1
    notes_1 = [
        InvestigationNote(
            incident_id=inc1.incident_id,
            analyst_name="Sarah Chen (Lead SOC Investigator)",
            note_text="Identified credential harvest URL embedded in spoofed Microsoft SharePoint notification sent to user r.simmons@enterprise-corp.com.",
            created_at=now - timedelta(hours=3, minutes=20)
        ),
        InvestigationNote(
            incident_id=inc1.incident_id,
            analyst_name="Sarah Chen (Lead SOC Investigator)",
            note_text="EDR agent detected spawned PowerShell process with base64 encoded flag calling out to 185.220.101.45. Requested host containment.",
            created_at=now - timedelta(hours=2, minutes=5)
        )
    ]
    for n in notes_1:
        db.add(n)

    # Actions for Incident 1
    actions_1 = [
        ResponseAction(
            incident_id=inc1.incident_id,
            action_type="FIREWALL_BLOCK",
            target="185.220.101.45",
            status="SIMULATED_EXECUTED",
            details="Simulated perimeter Palo Alto firewall rule pushed: Ingress/Egress DROP for IP 185.220.101.45.",
            is_simulated=True,
            executed_by="Sarah Chen",
            executed_at=now - timedelta(hours=2, minutes=0)
        ),
        ResponseAction(
            incident_id=inc1.incident_id,
            action_type="ENDPOINT_ISOLATION",
            target="FINANCE-WS-04",
            status="SIMULATED_EXECUTED",
            details="Simulated EDR host network isolation active. Only telemetry tunnel to EDR server preserved.",
            is_simulated=True,
            executed_by="Sarah Chen",
            executed_at=now - timedelta(hours=1, minutes=45)
        )
    ]
    for a in actions_1:
        db.add(a)

    # Events linked to Incident 1
    ev_inc1_a = SecurityEvent(
        event_id="SEC-2026-00101",
        timestamp=now - timedelta(hours=3, minutes=45),
        event_source="Email Gateway (SRC-M365-EMAIL)",
        threat_category="Phishing / Brand Impersonation",
        risk_score=92,
        severity="Critical",
        source_ip="185.220.101.45",
        dest_ip="10.0.12.84",
        domain="login-microsoft365-verify.xyz",
        file_hash=None,
        user_account="r.simmons@enterprise-corp.com",
        employee_id="EMP-1043",
        evidence="Inbound email subject 'URGENT: Review Shared Financial Document' containing high-risk spoofing domain.",
        analysis_status="Correlated",
        recommended_action="Quarantine email from all recipient inboxes and add domain to proxy sinkhole.",
        is_acknowledged=True,
        acknowledged_by="Sarah Chen",
        acknowledged_at=now - timedelta(hours=3, minutes=30),
        incident_id=inc1.incident_id
    )
    ev_inc1_b = SecurityEvent(
        event_id="SEC-2026-00102",
        timestamp=now - timedelta(hours=3, minutes=15),
        event_source="Endpoint Sensor (SRC-CRWD-EDR)",
        threat_category="Malicious Payload Execution",
        risk_score=95,
        severity="Critical",
        source_ip=None,
        dest_ip="10.0.12.84",
        domain=None,
        file_hash="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        user_account="r.simmons",
        employee_id="EMP-1043",
        evidence="High-entropy executable 'invoice_march_q1.scr' detected in %APPDATA% directory spawning cmd.exe.",
        analysis_status="Correlated",
        recommended_action="Quarantine artifact, isolate endpoint, and initiate process memory dump.",
        is_acknowledged=True,
        acknowledged_by="Sarah Chen",
        acknowledged_at=now - timedelta(hours=2, minutes=30),
        incident_id=inc1.incident_id
    )
    ev_inc1_c = SecurityEvent(
        event_id="SEC-2026-00103",
        timestamp=now - timedelta(hours=2, minutes=50),
        event_source="Network Zeek Sensor (SRC-ZEEK-NIDS)",
        threat_category="C2 Communication Spike",
        risk_score=90,
        severity="Critical",
        source_ip="10.0.12.84",
        dest_ip="185.220.101.45",
        domain=None,
        file_hash=None,
        user_account=None,
        employee_id="EMP-1043",
        evidence="Observed 12 periodic outbound beacon packets with 60s jitter to unindexed foreign host on port 443.",
        analysis_status="Correlated",
        recommended_action="Block target destination IP on all core switches and perimeter firewalls.",
        is_acknowledged=True,
        acknowledged_by="Sarah Chen",
        acknowledged_at=now - timedelta(hours=2, minutes=10),
        incident_id=inc1.incident_id
    )
    db.add_all([ev_inc1_a, ev_inc1_b, ev_inc1_c])

    # Incident 2: SSH Brute Force
    inc2 = Incident(
        incident_id="INC-2026-0043",
        title="Distributed SSH Credential Stuffing on DMZ Bastion",
        description="Repeated failed authentications exceeding security policy thresholds. 48 distinct usernames targeted across 3 minutes.",
        threat_category="Brute-Force / Credential Stuffing",
        severity="High",
        risk_score=78,
        status="Contained",
        assigned_analyst="David Vance (SecAdmin)",
        created_at=now - timedelta(hours=5, minutes=10),
        updated_at=now - timedelta(hours=4, minutes=30),
        correlation_reason="Correlated via single offending IP 194.26.29.112 targeting external bastion host bastion01.dmz.corp.",
        correlation_confidence="High Confidence (Deterministic Source IP Match)",
        forensic_summary="Automated SSH dictionary attack originated from known bulletproof VPS hosting provider. Blocklist triggered by SOC rule."
    )
    db.add(inc2)
    db.flush()

    ev_inc2 = SecurityEvent(
        event_id="SEC-2026-00104",
        timestamp=now - timedelta(hours=5, minutes=10),
        event_source="SSHD Auth Log (SRC-AZURE-IDP)",
        threat_category="Authentication Brute-Force",
        risk_score=78,
        severity="High",
        source_ip="194.26.29.112",
        dest_ip="172.16.50.4",
        domain=None,
        file_hash=None,
        user_account="root, admin, devops, deploy",
        employee_id=None,
        evidence="Recorded 48 failed SSH password attempts within 180 seconds using dictionary common passwords.",
        analysis_status="Correlated",
        recommended_action="Temporarily ban origin IP subnet and mandate SSH key-only authentication.",
        is_acknowledged=True,
        acknowledged_by="David Vance",
        acknowledged_at=now - timedelta(hours=4, minutes=50),
        incident_id=inc2.incident_id
    )
    db.add(ev_inc2)

    # Incident 3: Authorized Port Scan (False Positive)
    inc3 = Incident(
        incident_id="INC-2026-0044",
        title="Internal Vulnerability Assessment Port Sweep (Authorized)",
        description="Sequential port scan detected across internal subnet 10.0.100.0/24 originating from SecOps Nessus scanner.",
        threat_category="Port Reconnaissance",
        severity="Low",
        risk_score=25,
        status="False Positive",
        assigned_analyst="Sarah Chen (Lead SOC Investigator)",
        created_at=now - timedelta(hours=8),
        updated_at=now - timedelta(hours=7, minutes=30),
        correlation_reason="Internal IP 10.0.5.22 matched authorized SecOps Nessus scanner registry schedule.",
        correlation_confidence="High Confidence (Authorized Asset Whitelist)",
        forensic_summary="Alert confirmed as legitimate authorized weekly vulnerability scan ticket #SEC-CHG-8910. Alert closed as False Positive."
    )
    db.add(inc3)
    db.flush()

    ev_inc3 = SecurityEvent(
        event_id="SEC-2026-00105",
        timestamp=now - timedelta(hours=8),
        event_source="Internal Firewall Logs (SRC-PALO-NGFW)",
        threat_category="Port Scan",
        risk_score=25,
        severity="Low",
        source_ip="10.0.5.22",
        dest_ip="10.0.100.15",
        domain=None,
        file_hash=None,
        user_account=None,
        employee_id=None,
        evidence="Sequential TCP SYN probes across ports 21, 22, 80, 443, 8080, 8443.",
        analysis_status="Correlated",
        recommended_action="Suppress alert: Host is approved vulnerability scanner.",
        is_acknowledged=True,
        acknowledged_by="Sarah Chen",
        acknowledged_at=now - timedelta(hours=7, minutes=45),
        incident_id=inc3.incident_id
    )
    db.add(ev_inc3)

    # Unassigned Standalone Security Events
    ev_standalone = [
        SecurityEvent(
            event_id="SEC-2026-00106",
            timestamp=now - timedelta(hours=1, minutes=10),
            event_source="Cloudflare WAF",
            threat_category="SQL Injection Attempt",
            risk_score=85,
            severity="High",
            source_ip="103.251.167.20",
            dest_ip="172.16.10.80",
            domain="api.enterprise-corp.com",
            file_hash=None,
            user_account=None,
            employee_id=None,
            evidence="URL parameter contained: ' UNION SELECT username, password_hash FROM auth_users --",
            analysis_status="Analyzed",
            recommended_action="WAF blocked connection. Verify application parameterized query integrity.",
            is_acknowledged=False,
            incident_id=None
        ),
        SecurityEvent(
            event_id="SEC-2026-00107",
            timestamp=now - timedelta(minutes=45),
            event_source="Mail Filter (SRC-M365-EMAIL)",
            threat_category="CEO Impersonation Wire Fraud (BEC)",
            risk_score=88,
            severity="High",
            source_ip="209.85.220.41",
            dest_ip="10.0.12.5",
            domain="ceo-urgent-office.com",
            file_hash=None,
            user_account="alex.turner@enterprise-corp.com",
            employee_id="EMP-1042",
            evidence="Subject: 'QUICK WIRE TRANSFER REQUEST - CONFIDENTIAL'. Display name spoofing Chief Executive Officer.",
            analysis_status="Analyzed",
            recommended_action="Quarantine message across Exchange and alert Finance department of targeted BEC attempt.",
            is_acknowledged=False,
            incident_id=None
        ),
        SecurityEvent(
            event_id="SEC-2026-00108",
            timestamp=now - timedelta(minutes=20),
            event_source="Endpoint Sensor (SRC-CRWD-EDR)",
            threat_category="Suspicious Script Execution",
            risk_score=68,
            severity="Medium",
            source_ip=None,
            dest_ip="10.0.12.110",
            domain=None,
            file_hash="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            user_account="alex.turner",
            employee_id="EMP-1042",
            evidence="WScript.Shell execution of temp file with base64 encoded command arguments.",
            analysis_status="Analyzed",
            recommended_action="Isolate host from local subnet and inspect parent process execution tree.",
            is_acknowledged=False,
            incident_id=None
        ),
        SecurityEvent(
            event_id="SEC-2026-00109",
            timestamp=now - timedelta(minutes=8),
            event_source="DNS Resolver (SRC-CISCO-DNS)",
            threat_category="DNS Tunneling Anomaly",
            risk_score=72,
            severity="Medium",
            source_ip="10.0.12.190",
            dest_ip="10.0.0.2",
            domain="x89f2a.tunnel.cdn-updates.xyz",
            file_hash=None,
            user_account="elena.r",
            employee_id="EMP-1044",
            evidence="High volume of TXT record queries with abnormal character entropy (6.8 bits/char).",
            analysis_status="Analyzed",
            recommended_action="Sinkhole apex domain on internal recursive DNS and triage workstation IP 10.0.12.190.",
            is_acknowledged=False,
            incident_id=None
        )
    ]
    db.add_all(ev_standalone)

    # Audit Trail
    audit_entries = [
        AuditLog(
            action="SYSTEM_INIT",
            actor="System Bootstrap",
            resource_type="Platform",
            resource_id="CYBERSHIELD-CORE",
            details="Initialized SOC enterprise schema with 4 RBAC users, 6 employees, 7 monitoring sources, and DLP findings."
        )
    ]
    db.add_all(audit_entries)
    db.flush()
    db.query(SecurityEvent).update({SecurityEvent.is_simulated: True})   # everything seeded is fabricated
    db.commit()

    return {"status": "success", "message": "Enterprise cybersecurity dataset successfully populated."}
