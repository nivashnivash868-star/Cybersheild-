import uuid
import collections
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from app.schemas import NetworkRecordInput, NetworkAnomalyAlert, NetworkAnalysisBatchResponse

import csv
import ipaddress
import random
from pathlib import Path

from app.config import settings

# Thresholds. They are starting points for a typical office network; docs/detection-evaluation.md shows how they behave.
PORT_SCAN_THRESHOLD = 10        # distinct destination ports probed on ONE destination host by one source in a batch
BRUTE_FORCE_THRESHOLD = 5       # failed logins from one source in a batch
DATA_EXFIL_BYTE_THRESHOLD = 50_000_000   # a single flow to an external address
BACKDOOR_PORTS = {4444: "Metasploit default listener", 1337: "common backdoor port", 31337: "classic backdoor port"}
RISKY_PORTS = {23: "Telnet (cleartext remote shell)", 6667: "IRC (common botnet command channel)"}

PORT_CLASSES = ((53, 123), (80, 443, 8080, 8443), (25, 465, 587, 993, 995, 143, 110), (22, 3389, 5900),
                (1433, 3306, 5432, 1521, 27017, 6379))


def port_class(port: int) -> int:
    for i, group in enumerate(PORT_CLASSES):
        if port in group:
            return i
    return len(PORT_CLASSES) if port < 1024 else len(PORT_CLASSES) + 1


def flow_features(port: int, nbytes: int, packets: int) -> List[float]:
    packets = max(packets, 1)
    return [float(port_class(port)), float(np.log10(nbytes + 1)), float(np.log10(packets + 1)), float(np.log10(nbytes / packets + 1))]


def trusted_destinations() -> list:
    nets = []
    for part in (settings.NETWORK_TRUSTED_DESTINATIONS or "").split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return nets


def is_trusted(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def is_external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def synthetic_flows(n: int = 6000, seed: int = 11) -> List[Tuple[int, int, int]]:
    """Plausible ordinary office traffic, generated: web, DNS, mail, NTP, SSH, databases. A stand-in until the organisation's
    own traffic is supplied through NETWORK_BASELINE_CSV (columns: dst_port, bytes, packets)."""
    rng = random.Random(seed)
    profiles = [  # (weight, ports, median bytes, spread, median packets)
        (0.45, (443, 443, 80, 8443), 18_000, 1.1, 22), (0.2, (53,), 300, 0.4, 2), (0.08, (123,), 120, 0.2, 2),
        (0.1, (993, 587, 465, 143), 22_000, 1.0, 25), (0.05, (22,), 9_000, 1.2, 40), (0.04, (3389,), 150_000, 1.0, 180),
        (0.05, (5432, 3306, 1433), 60_000, 1.1, 60), (0.03, (8080,), 12_000, 1.0, 15)]
    out = []
    for _ in range(n):
        r, acc = rng.random(), 0.0
        for weight, ports, med, spread, pk in profiles:
            acc += weight
            if r <= acc:
                break
        b = int(min(med * rng.lognormvariate(0, spread), 20_000_000))
        out.append((rng.choice(ports), b, max(1, int(pk * rng.lognormvariate(0, 0.6)))))
    return out


def synthetic_baseline(n: int = 6000, seed: int = 11) -> np.ndarray:
    return np.array([flow_features(*f) for f in synthetic_flows(n, seed)])


def baseline_from_csv(path: str) -> Optional[np.ndarray]:
    rows = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                try:
                    rows.append(flow_features(int(r["dst_port"]), int(float(r["bytes"])), int(float(r["packets"]))))
                except (KeyError, ValueError):
                    continue
    except OSError:
        return None
    return np.array(rows) if len(rows) >= 500 else None


class NetworkAnomalyDetector:
    def __init__(self):
        self._init_isolation_forest()

    def _init_isolation_forest(self):
        """Fit an IsolationForest on the organisation's own benign traffic if NETWORK_BASELINE_CSV is set, otherwise on a
        generated office-traffic baseline. `baseline_source` says which, and is shown in results."""
        data = baseline_from_csv(settings.NETWORK_BASELINE_CSV) if settings.NETWORK_BASELINE_CSV else None
        self.baseline_source = "organisation traffic" if data is not None else "generated office-traffic baseline"
        if data is None:
            data = synthetic_baseline()
        self.iso_forest = IsolationForest(n_estimators=200, contamination=0.005, random_state=42)
        self.iso_forest.fit(data)

    def analyze_batch(self, records: List[NetworkRecordInput], include_ml: bool = True) -> NetworkAnalysisBatchResponse:
        alerts: List[NetworkAnomalyAlert] = []
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Stateful aggregators for correlation across batch
        pair_ports = collections.defaultdict(set)
        failed_auth_map = collections.defaultdict(list)

        for rec in records:
            pair_ports[(rec.source_ip, rec.destination_ip)].add(rec.destination_port)
            if rec.auth_status and rec.auth_status.upper() == "FAILED":
                failed_auth_map[rec.source_ip].append(rec)

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

        # 2. Rule 2: one source probing many ports on one host
        for (src_ip, dst_ip), ports in pair_ports.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                sample_rec = next(r for r in records if r.source_ip == src_ip and r.destination_ip == dst_ip)
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-SCAN-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=sample_rec.timestamp or now_str,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=0,
                    protocol=sample_rec.protocol,
                    event_type="Suspicious Port Reconnaissance",
                    severity="High",
                    risk_score=78,
                    detection_reason=f"{src_ip} probed {len(ports)} distinct ports on {dst_ip} ({', '.join(str(p) for p in sorted(ports)[:6])}...), consistent with a port scan.",
                    recommended_response="Block the source at the perimeter and check the target host for exposed services.",
                    evidence_tokens=[
                        f"DistinctPortsScanned={len(ports)}",
                        f"PortSample={','.join(str(p) for p in sorted(ports)[:5])}",
                        f"DestTarget={dst_ip}"
                    ],
                    engine="Port dispersion rule"
                ))
                for r in records:
                    if r.source_ip == src_ip and r.destination_ip == dst_ip:
                        analyzed_indices.add(id(r))

        # 2b. Volume sent from one source to one external destination, summed across the batch (a copy split over
        #     several connections is still one copy)
        trusted = trusted_destinations()
        egress = collections.defaultdict(list)
        for rec in records:
            if is_external(rec.destination_ip) and not is_external(rec.source_ip) and not is_trusted(rec.destination_ip, trusted):
                egress[(rec.source_ip, rec.destination_ip)].append(rec)
        for (src_ip, dst_ip), flows in egress.items():
            total = sum(f.bytes_transferred for f in flows)
            if total >= DATA_EXFIL_BYTE_THRESHOLD:
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-EXFIL-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=flows[0].timestamp or now_str,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=flows[0].destination_port,
                    protocol=flows[0].protocol,
                    event_type="Unexpected Traffic Spike / Exfiltration",
                    severity="Critical",
                    risk_score=92,
                    detection_reason=f"{round(total / (1024*1024), 1)} MB went from {src_ip} to the external address {dst_ip} in {len(flows)} flow(s).",
                    recommended_response="Confirm whether this is an expected upload or backup; if not, cut the connection and preserve flow records for forensics.",
                    evidence_tokens=[f"BytesTransferred={total}", f"Flows={len(flows)}", f"DestPort={flows[0].destination_port}"],
                    engine="Egress volume threshold"
                ))
                for f in flows:
                    analyzed_indices.add(id(f))

        # 3. Rule 3: large external transfers, risky ports, and statistical outliers (scored in one pass)
        ml_result = {}
        if include_ml and records:
            matrix = np.array([flow_features(r.destination_port, r.bytes_transferred, r.packet_count) for r in records])
            predictions, raw_scores = self.iso_forest.predict(matrix), self.iso_forest.score_samples(matrix)
            ml_result = {id(r): (predictions[i], raw_scores[i]) for i, r in enumerate(records)}
        for rec in records:
            if id(rec) in analyzed_indices:
                continue

            # Ports that legitimate office traffic rarely uses
            known = BACKDOOR_PORTS.get(rec.destination_port) or RISKY_PORTS.get(rec.destination_port)
            if known:
                backdoor = rec.destination_port in BACKDOOR_PORTS
                alerts.append(NetworkAnomalyAlert(
                    event_id=f"NET-C2-{uuid.uuid4().hex[:10].upper()}",
                    timestamp=rec.timestamp or now_str,
                    source_ip=rec.source_ip,
                    destination_ip=rec.destination_ip,
                    destination_port=rec.destination_port,
                    protocol=rec.protocol,
                    event_type="Suspected C2 Communication / Backdoor Port" if backdoor else "Risky Service Port",
                    severity="Critical" if backdoor else "High",
                    risk_score=90 if backdoor else 70,
                    detection_reason=f"Connection to port {rec.destination_port}: {known}.",
                    recommended_response="Check what process on the source host opened this connection." if not backdoor else "Isolate the source host pending triage.",
                    evidence_tokens=[
                        f"Port={rec.destination_port}",
                        f"Direction={rec.source_ip}->{rec.destination_ip}",
                        f"Protocol={rec.protocol}"
                    ],
                    engine="Risky port rule"
                ))
                analyzed_indices.add(id(rec))
                continue

            if not include_ml:
                continue

            # Statistical outlier relative to the baseline traffic
            prediction, raw_score = ml_result[id(rec)]
            if prediction == -1:
                score_val = min(max(int(abs(raw_score) * 100), 55), 85)
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
                    detection_reason=f"This flow (port {rec.destination_port}, {rec.bytes_transferred} bytes, {rec.packet_count} packets) is unusual compared with the {self.baseline_source}.",
                    recommended_response="Check whether this matches a known job such as a backup or a software update.",
                    evidence_tokens=[f"AnomalyScore={score_val}", f"Bytes={rec.bytes_transferred}", f"Packets={rec.packet_count}", f"Port={rec.destination_port}"],
                    engine="Isolation Forest"
                ))
                analyzed_indices.add(id(rec))

        benign_count = max(0, len(records) - len(alerts))

        return NetworkAnalysisBatchResponse(
            total_records_analyzed=len(records),
            anomalies_detected=len(alerts),
            benign_count=benign_count,
            engine_used=f"Rules + Isolation Forest (baseline: {self.baseline_source})",
            alerts=alerts
        )

network_detector = NetworkAnomalyDetector()
