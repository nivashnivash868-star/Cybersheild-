#!/usr/bin/env python3
"""A minimal receiver for CyberShield's response connector, for testing the wiring end to end.

It verifies the HMAC signature, prints what it was asked to do (it does NOT disable anything), answers 202, then reports
success through the signed callback. Replace the `perform` function with a call to your identity provider, EDR or SOAR.

    RESPONSE_WEBHOOK_SECRET=<same 32+ char secret as CyberShield> python scripts/example_response_receiver.py --port 9009
    # CyberShield: RESPONSE_WEBHOOK_URL=http://127.0.0.1:9009/hook  RESPONSE_WEBHOOK_SECRET=<same secret>

Standard library only.
"""
import argparse
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("RESPONSE_WEBHOOK_SECRET", "")


def sign(body: bytes) -> str:
    ts = int(time.time())
    return f"t={ts},v1=" + hmac.new(SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


def verify(body: bytes, header: str) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts, given = int(parts["t"]), parts["v1"]
    except (ValueError, KeyError):
        return False
    expected = hmac.new(SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return abs(time.time() - ts) <= 300 and hmac.compare_digest(expected, given)


def perform(job: dict) -> tuple:
    """Do the work here. Return (succeeded, detail)."""
    print(f"  would run: {job['action']} on {job['target']} (incident {job['incident_id']}, approved by {job['approved_by']})")
    return True, "example receiver: nothing was changed"


def report_back(job: dict) -> None:
    ok, detail = perform(job)
    body = json.dumps({"job_id": job["job_id"], "result": "succeeded" if ok else "failed", "detail": detail}).encode()
    req = urllib.request.Request(job["callback_url"], data=body, headers={"Content-Type": "application/json", "X-CyberShield-Signature": sign(body)})
    try:
        print("  callback ->", urllib.request.urlopen(req, timeout=10).status)
    except Exception as exc:  # noqa: BLE001
        print("  callback failed:", exc)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not verify(body, self.headers.get("X-CyberShield-Signature", "")):
            self.send_response(401)
            self.end_headers()
            return
        job = json.loads(body)
        print(f"accepted {job['job_id']}")
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"accepted"}')
        threading.Thread(target=report_back, args=(job,), daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9009)
    args = ap.parse_args()
    if len(SECRET) < 32:
        raise SystemExit("Set RESPONSE_WEBHOOK_SECRET to the same 32+ character secret CyberShield uses.")
    print(f"listening on 127.0.0.1:{args.port}")
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
