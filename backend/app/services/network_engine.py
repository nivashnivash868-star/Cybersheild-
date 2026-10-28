import uuid
import collections
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from app.schemas import NetworkRecordInput, NetworkAnomalyAlert, NetworkAnalysisBatchResponse

# Suspicious port scanning thresholds
PORT_SCAN_THRESHOLD = 4  # Hits on >4 distinct ports within single source IP in record batch
BRUTE_FORCE_THRESHOLD = 3 # Repeated failed logins from single source IP
DATA_EXFIL_BYTE_THRESHOLD = 5000000 # 5MB single connection spike

class NetworkAnomalyDetector:
    def __init__(self):
        self._init_isolation_forest()

    def _init_isolation_forest(self):
        """
        Train baseline Isolation Forest model on nominal network traffic features:
        [port, bytes_transferred, packet_count]
        """
        nominal_traffic = np.array([
            # port, bytes, packets
            [443, 14200, 18],
            [80, 5200, 8],
            [443, 28000, 32],
            [53, 312, 2],
            [443, 8900, 12],
            [123, 120, 2],
            [443, 45000, 48],
            [8080, 3200, 6],
            [443, 19200, 22],
            [53, 280, 2],
            [993, 8500, 10],
            [443, 124000, 110],
        ])
        self.iso_forest = IsolationForest(contamination=0.15, random_state=42)
        self.iso_forest.fit(nominal_traffic)

    def analyze_batch(self, records: List[NetworkRecordInput], include_ml: bool = True) -> NetworkAnalysisBatchResponse:
        alerts: List[NetworkAnomalyAlert] = []
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Stateful aggregators for correlation across batch
        src_port_map = collections.defaultdict(set)
        failed_auth_map = collections.defaultdict(list)
        src_ip_volume = collections.defaultdict(int)

        for rec in records:
            src_port_map[rec.source_ip].add(rec.destination_port)
            if rec.auth_status and rec.auth_status.upper() == "FAILED":
                failed_auth_map[rec.source_ip].append(rec)
            src_ip_volume[rec.source_ip] += rec.bytes_transferred

        analyzed_indices = set()

        # 1. Rule 1: Brute Force Authentication Floods
        for src_ip, fails in failed_auth_map.items():
            if len(fails) >= BRUTE_FORCE_THRESHOLD:
                first_rec = fails[0]
                target_user = first_rec.user_account or "root/admin"
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-BRUTE-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=first_rec.timestamp or now_str,
                    source_ip=src_ip,
                    destination_ip=first_rec.destination_ip,
                    destination_port=first_rec.destination_port,
                    protocol=first_rec.protocol,
                    event_type="Authentication Brute-Force",
                    severity="High",
                    risk_score=82,
                    detection_reason=f"Detected {len(fails)} sequential failed login attempts targeting account '{target_user}'.",
                    recommended_response="Enforce temporary IP rate-limit/ban on perimeter firewall and lock affected user credential pending SOC validation.",
                    evidence_tokens=[
                        f"FailedAttempts={len(fails)}",
                        f"TargetAccount={target_user}",
                        f"Protocol={first_rec.protocol}",
                        f"Port={first_rec.destination_port}"
                    ],
                    engine="Stateful Correlation Rule: Auth Failure Frequency"
                ))
                for f in fails:
                    analyzed_indices.add(id(f))

        # 2. Rule 2: Sequential Port Scanning Patterns
        for src_ip, ports in src_port_map.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                # Find a sample record for IPs
                sample_rec = next(r for r in records if r.source_ip == src_ip)
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-SCAN-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=sample_rec.timestamp or now_str,
                    source_ip=src_ip,
                    destination_ip=sample_rec.destination_ip,
                    destination_port=0,
                    protocol=sample_rec.protocol,
                    event_type="Suspicious Port Reconnaissance",
                    severity="High",
                    risk_score=78,
                    detection_reason=f"Host probed {len(ports)} distinct ports ({', '.join(str(p) for p in sorted(list(ports))[:6])}) indicative of Nmap/SYN reconnaissance.",
                    recommended_response="Blacklist source IP on perimeter ingress ACLs; inspect destination host for exposed listeners.",
                    evidence_tokens=[
                        f"DistinctPortsScanned={len(ports)}",
                        f"PortSample={','.join(str(p) for p in sorted(list(ports))[:5])}",
                        f"DestTarget={sample_rec.destination_ip}"
                    ],
                    engine="Stateful Port Dispersion Rule"
                ))
                for r in records:
                    if r.source_ip == src_ip:
                        analyzed_indices.add(id(r))

        # 3. Rule 3: Anomalous Data Volume Spikes & Isolation Forest ML Anomaly
        for rec in records:
            if id(rec) in analyzed_indices:
                continue

            # Data Exfiltration Rule
            if rec.bytes_transferred >= DATA_EXFIL_BYTE_THRESHOLD:
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-EXFIL-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=rec.timestamp or now_str,
                    source_ip=rec.source_ip,
                    destination_ip=rec.destination_ip,
                    destination_port=rec.destination_port,
                    protocol=rec.protocol,
                    event_type="Unexpected Traffic Spike / Exfiltration",
                    severity="Critical",
                    risk_score=92,
                    detection_reason=f"Massive outbound egress spike ({round(rec.bytes_transferred / (1024*1024), 2)} MB) to unindexed destination.",
                    recommended_response="Sever active TCP socket connection immediately; preserve full PCAP for digital forensics triage.",
                    evidence_tokens=[
                        f"BytesTransferred={rec.bytes_transferred}",
                        f"Packets={rec.packet_count}",
                        f"DestPort={rec.destination_port}"
                    ],
                    engine="Egress Volume Threshold Engine"
                ))
                analyzed_indices.add(id(rec))
                continue

            # High-risk remote admin ports (e.g. 4444 Metasploit, 3389 RDP exposed to WAN, 23 Telnet)
            if rec.destination_port in [4444, 1337, 6667, 23, 31337]:
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-C2-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=rec.timestamp or now_str,
                    source_ip=rec.source_ip,
                    destination_ip=rec.destination_ip,
                    destination_port=rec.destination_port,
                    protocol=rec.protocol,
                    event_type="Suspected C2 Communication / Backdoor Port",
                    severity="Critical",
                    risk_score=94,
                    detection_reason=f"Connection attempt targeting known adversary backdoor/C2 port ({rec.destination_port}).",
                    recommended_response="Isolate internal endpoint host from subnet; conduct RAM triage for memory-injected payloads.",
                    evidence_tokens=[
                        f"HighRiskPort={rec.destination_port}",
                        f"Direction={rec.source_ip}->{rec.destination_ip}",
                        f"Protocol={rec.protocol}"
                    ],
                    engine="Known Threat Port Heuristic"
                ))
                analyzed_indices.add(id(rec))
                continue

            if not include_ml:
                continue

            # Scikit-learn Isolation Forest ML Anomaly Check
            sample_features = np.array([[rec.destination_port, rec.bytes_transferred, rec.packet_count]])
            ml_pred = self.iso_forest.predict(sample_features)[0]  # -1 is anomaly, 1 is normal
            if ml_pred == -1 and (rec.bytes_transferred > 80000 or rec.packet_count > 90):
                score_val = int(abs(self.iso_forest.score_samples(sample_features)[0]) * 100)
                score_val = min(max(score_val, 65), 89)
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-ISO-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=rec.timestamp or now_str,
                    source_ip=rec.source_ip,
                    destination_ip=rec.destination_ip,
                    destination_port=rec.destination_port,
                    protocol=rec.protocol,
                    event_type="Multivariate Statistical Traffic Anomaly",
                    severity="Medium",
                    risk_score=score_val,
                    detection_reason="Isolation Forest detected statistical outlier in multi-dimensional space (port, byte payload volume, packet count).",
                    recommended_response="Inspect application flow telemetry and confirm if volume spike aligns with scheduled batch backups.",
                    evidence_tokens=[
                        f"MLOutlierScore={score_val}",
                        f"Bytes={rec.bytes_transferred}",
                        f"Packets={rec.packet_count}",
                        f"Port={rec.destination_port}"
                    ],
                    engine="Scikit-Learn Isolation Forest Anomaly Engine"
                ))
                analyzed_indices.add(id(rec))

        benign_count = max(0, len(records) - len(alerts))

        return NetworkAnalysisBatchResponse(
            total_records_analyzed=len(records),
            anomalies_detected=len(alerts),
            benign_count=benign_count,
            engine_used="Rule-Based Signature Match + Scikit-Learn Isolation Forest Anomaly Detector",
            alerts=alerts
        )

network_detector = NetworkAnomalyDetector()
