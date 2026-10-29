"""Network detector evaluation: false alarms on fresh ordinary traffic, and detection of constructed attacks.

The ordinary traffic comes from the same generator that builds the default baseline (different seed), so the
false-alarm figure says how the model treats traffic like its baseline, NOT how it treats your network. Fit it on your own
flows (NETWORK_BASELINE_CSV) and measure again before trusting it.
"""
import random

from app.schemas import NetworkRecordInput
from app.services.network_engine import network_detector, synthetic_flows


def evaluate_network():
    out = {"baseline": network_detector.baseline_source}
    rng = random.Random(5)
    benign = [NetworkRecordInput(source_ip=f"10.0.{rng.randint(0, 9)}.{rng.randint(2, 250)}", destination_ip=f"52.{rng.randint(1, 200)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
                                 destination_port=p, bytes_transferred=b, packet_count=k) for p, b, k in synthetic_flows(10000, seed=99)]
    for label, ml in (("rules_only", False), ("rules_plus_isolation_forest", True)):
        r = network_detector.analyze_batch(benign, include_ml=ml)
        out[f"benign_{label}"] = {"flows": len(benign), "alerts": r.anomalies_detected, "false_alarm_rate": f"{100 * r.anomalies_detected / len(benign):.2f}%",
                                  "by_type": {t: sum(a.event_type == t for a in r.alerts) for t in {a.event_type for a in r.alerts}}}
    attacks = {
        "port scan (25 ports)": [NetworkRecordInput(source_ip="45.155.205.233", destination_ip="10.20.0.1", destination_port=p) for p in range(20, 45)],
        "SSH brute force (30 failures)": [NetworkRecordInput(source_ip="45.155.205.233", destination_ip="10.20.0.9", destination_port=22, auth_status="FAILED", user_account="root") for _ in range(30)],
        "120 MB upload to external host": [NetworkRecordInput(source_ip="10.20.4.37", destination_ip="185.220.101.47", destination_port=443, bytes_transferred=120_000_000, packet_count=90000)],
        "backdoor port 4444": [NetworkRecordInput(source_ip="10.20.4.37", destination_ip="185.220.101.47", destination_port=4444, bytes_transferred=900, packet_count=6)],
        "6 x 20 MB copy to external host (split across flows)": [NetworkRecordInput(source_ip="10.20.4.37", destination_ip="185.220.101.47", destination_port=443, bytes_transferred=20_000_000, packet_count=14000) for _ in range(6)],
        "20 MB single upload (below threshold)": [NetworkRecordInput(source_ip="10.20.4.37", destination_ip="185.220.101.47", destination_port=443, bytes_transferred=20_000_000, packet_count=14000)],
        "tiny beacon flows to port 8081": [NetworkRecordInput(source_ip="10.20.4.37", destination_ip="185.220.101.47", destination_port=8081, bytes_transferred=40, packet_count=1)],
    }
    out["attacks"] = {}
    for name, recs in attacks.items():
        r = network_detector.analyze_batch(recs, include_ml=True)
        out["attacks"][name] = sorted({a.event_type for a in r.alerts}) or "MISSED"
    normal_scan = [NetworkRecordInput(source_ip="10.0.1.5", destination_ip=f"52.1.1.{i}", destination_port=p) for i, p in enumerate((80, 443, 53, 22, 993, 587, 8080))]
    out["normal_mixed_ports_across_many_hosts"] = network_detector.analyze_batch(normal_scan, include_ml=False).anomalies_detected
    return out
