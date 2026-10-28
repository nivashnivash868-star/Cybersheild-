#!/usr/bin/env python3
"""Generates SYNTHETIC security logs to load into Zetaris for testing and demos.

Everything here is fabricated: names, addresses and events are invented and the "attack" is a scripted story. Do
not present it as real telemetry. Replace it with your own sources by pointing ZETARIS_TABLE_* at real tables.

Writes three CSVs (UTC timestamps, 'YYYY-MM-DD HH:MM:SS') with the columns CyberShield reads by default:
  synthetic_auth_logs.csv      event_id, event_time, username, src_ip, result
  synthetic_network_flows.csv  flow_id, event_time, src_ip, dst_ip, dst_port, protocol, bytes, packets
  synthetic_email_logs.csv     message_id, event_time, sender, recipient, subject, body

The planted story (all within the last few hours so a default 72h lookback sees it):
  T-5h   phishing email to priya.s@enterprise-corp.com from a look-alike domain
  T-3h   port scan against the internal gateway from 45.155.205.233
  T-2h   burst of failed logins for priya.s from the same address, then a successful login
  T-1h   ~120 MB outbound transfer from priya's workstation to 185.220.101.47
plus benign traffic for 40 employees so the signal has to be found.

Usage: python scripts/generate_synthetic_logs.py [--out data/synthetic] [--seed 7]
"""
import argparse
import csv
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

ATTACKER = "45.155.205.233"
EXFIL_DEST = "185.220.101.47"
VICTIM = "priya.s@enterprise-corp.com"
VICTIM_HOST = "10.20.4.37"
DOMAIN = "enterprise-corp.com"
FIRST = ["alex", "sam", "jo", "maria", "chen", "ravi", "li", "nora", "omar", "ines", "tom", "zara", "ben", "uma", "kai"]
LAST = ["turner", "k", "simmons", "r", "thorne", "p", "drake", "m", "v", "t"]
PUBLIC_SITES = ["142.250.74.46", "151.101.1.69", "13.107.42.14", "52.96.108.2", "140.82.112.3", "104.18.32.7"]


def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def build(seed: int):
    rng = random.Random(seed)
    now = datetime.utcnow().replace(microsecond=0)
    users = sorted({f"{rng.choice(FIRST)}.{rng.choice(LAST)}@{DOMAIN}" for _ in range(60)})[:40] + [VICTIM]
    ips = {u: f"10.20.{rng.randint(1, 9)}.{rng.randint(10, 250)}" for u in users}
    ips[VICTIM] = VICTIM_HOST
    auth, flows, mails = [], [], []

    # benign: logins (a few typos), flows, ordinary mail
    for _ in range(1800):
        u, t = rng.choice(users), now - timedelta(seconds=rng.randint(0, 6 * 3600))
        ok = rng.random() > 0.04
        auth.append((uuid.uuid4().hex, fmt(t), u, ips[u], "SUCCESS" if ok else "FAILURE"))
    for _ in range(6000):
        u, t = rng.choice(users), now - timedelta(seconds=rng.randint(0, 6 * 3600))
        flows.append((uuid.uuid4().hex, fmt(t), ips[u], rng.choice(PUBLIC_SITES), rng.choice([443, 443, 443, 80, 53]),
                      "TCP", rng.randint(300, 90_000), rng.randint(2, 70)))
    subjects = ["Lunch on Friday?", "Sprint planning notes", "Updated holiday calendar", "Invoice 2217 attached",
                "Meeting moved to 3pm", "Quarterly review draft"]
    for i in range(250):
        s, r = rng.sample(users, 2)
        t = now - timedelta(seconds=rng.randint(0, 6 * 3600))
        mails.append((f"benign-{i}", fmt(t), s, r, rng.choice(subjects), "Hi, just following up on the earlier thread. Thanks."))

    # the planted story
    mails.append(("story-phish-1", fmt(now - timedelta(hours=5)), "it-support@micr0soft-verify.xyz", VICTIM,
                  "Urgent: verify your account now",
                  "Your account will be suspended. Click http://login-microsoft365-verify.xyz/auth to verify your "
                  "password immediately."))
    for port in (21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080):
        flows.append((uuid.uuid4().hex, fmt(now - timedelta(hours=3, seconds=rng.randint(0, 120))), ATTACKER,
                      "10.20.0.1", port, "TCP", rng.randint(60, 300), rng.randint(1, 3)))
    for i in range(14):
        auth.append((uuid.uuid4().hex, fmt(now - timedelta(hours=2, seconds=-i * 20)), VICTIM, ATTACKER, "FAILURE"))
    auth.append((uuid.uuid4().hex, fmt(now - timedelta(hours=2, seconds=-400)), VICTIM, ATTACKER, "SUCCESS"))
    for i in range(6):
        flows.append((uuid.uuid4().hex, fmt(now - timedelta(hours=1, seconds=-i * 30)), VICTIM_HOST, EXFIL_DEST, 443,
                      "TCP", 20_000_000, 14_000))
    return auth, flows, mails


def write(path: Path, header, rows) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(sorted(rows, key=lambda r: r[1] if "flow" not in header[0] else r[1]))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/synthetic")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    auth, flows, mails = build(args.seed)
    write(out / "synthetic_auth_logs.csv", ["event_id", "event_time", "username", "src_ip", "result"], auth)
    write(out / "synthetic_network_flows.csv",
          ["flow_id", "event_time", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "packets"], flows)
    write(out / "synthetic_email_logs.csv", ["message_id", "event_time", "sender", "recipient", "subject", "body"], mails)
    print(f"Wrote SYNTHETIC data to {out}/: {len(auth)} auth rows, {len(flows)} flows, {len(mails)} emails.")
    print(f"Planted story: attacker {ATTACKER} -> victim {VICTIM}; exfiltration to {EXFIL_DEST}.")


if __name__ == "__main__":
    main()
