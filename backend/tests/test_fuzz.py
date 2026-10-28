"""Schema-driven fuzzing: every API operation, as every role, with valid and hostile input. No request may cause a 5xx.

Operations are taken from the OpenAPI schema, so a newly added route is fuzzed automatically. Operations that would
end the test session or reset shared state are skipped explicitly.
"""
import itertools
import random

import httpx
import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.services.demo_data_seeder import seed_demo_soc_data
from tests.conftest import ACCOUNTS, login
from app.config import settings

API = "/api/v1"
SKIP = {
    ("POST", f"{API}/system/seed-demo"),          # wipes the shared database
    ("POST", f"{API}/auth/logout"), ("POST", f"{API}/auth/logout-all"),
    ("POST", f"{API}/auth/change-password"), ("POST", f"{API}/auth/mfa/setup"), ("POST", f"{API}/auth/mfa/enable"),
    ("POST", f"{API}/auth/mfa/disable"), ("POST", f"{API}/auth/mfa/verify"), ("POST", f"{API}/auth/login"),
    ("PUT", f"{API}/auth/profile"),
}
EVIL = ["", " ", "x" * 70000, "' OR '1'='1", "'; DROP TABLE users; --", "<script>alert(1)</script>", "../../etc/passwd",
        "\x00null\x00", "%s%s%s%s", "${jndi:ldap://x}", "ünïcödé-🔥", "\n\r\nBcc: x@evil.test", "{{7*7}}", "-1", "9" * 40, "NaN"]
PATH_GUESS = {"incident_id": "INC-FUZZ", "event_id": "SEC-FUZZ", "employee_id": "EMP-1042", "finding_id": "DLP-FUZZ",
              "source_id": "SRC-M365-EMAIL", "feed": "ip"}


@pytest.fixture(scope="module", autouse=True)
def _restore_seed_afterwards():
    yield
    with SessionLocal() as db:
        seed_demo_soc_data(db=db, force_reset=True)


def _spec():
    return app.openapi()


def _resolve(schema, spec):
    while "$ref" in schema:
        schema = spec["components"]["schemas"][schema["$ref"].split("/")[-1]]
    return schema


def gen(schema, spec, mode, rng, depth=0):
    schema = _resolve(schema or {}, spec)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [s for s in schema[key] if s.get("type") != "null"] or schema[key]
            return gen(options[0], spec, mode, rng, depth)
    if "allOf" in schema:
        return gen(schema["allOf"][0], spec, mode, rng, depth)
    t = schema.get("type")
    if mode == "wrongtype":
        return rng.choice([None, 12345, True, ["x"], {"k": "v"}, "wrong", -1.5])
    if mode == "evil" and t in ("string", None) and rng.random() < 0.8:
        return rng.choice(EVIL)
    if t == "object" or "properties" in schema:
        out = {}
        for name, sub in (schema.get("properties") or {}).items():
            if name in schema.get("required", []) or rng.random() < 0.7:
                out[name] = gen(sub, spec, mode, rng, depth + 1)
        return out
    if t == "array":
        return [gen(schema.get("items", {}), spec, mode, rng, depth + 1)] if depth < 3 else []
    if t == "integer":
        return rng.choice([0, 1, 2, -1, 999999999999, 24]) if mode != "valid" else max(schema.get("minimum", 1), 1)
    if t == "number":
        return 1.5
    if t == "boolean":
        return rng.choice([True, False])
    if "enum" in schema:
        return rng.choice(schema["enum"])
    if "pattern" in schema and mode == "valid":
        return "High"
    if t == "string" or t is None:
        return "valid-text" if mode == "valid" else rng.choice(EVIL)
    return None


def operations():
    spec = _spec()
    for path, ops in spec["paths"].items():
        if not path.startswith(API):
            continue
        for method, op in ops.items():
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE") and (method.upper(), path) not in SKIP:
                yield method.upper(), path, op


def build(path, op, spec, mode, rng):
    url, query = path, {}
    for p in op.get("parameters", []):
        sch = _resolve(p.get("schema", {}), spec)
        val = PATH_GUESS.get(p["name"]) or (rng.choice(["1", "999999", "x"]) if sch.get("type") == "integer" or p["in"] == "path" else None)
        if p["in"] == "path":
            url = url.replace("{" + p["name"] + "}", str(val if mode != "evil" else rng.choice(["1", "%00", "..%2f", "x" * 300])))
        elif p["in"] == "query" and (p.get("required") or rng.random() < 0.6):
            query[p["name"]] = str(gen(sch, spec, mode, rng)) if mode != "valid" else str(gen(sch, spec, "valid", rng))
    body = None
    rb = op.get("requestBody", {}).get("content", {})
    if "application/json" in rb:
        body = gen(rb["application/json"]["schema"], spec, mode, rng)
    return url, query, body, ("multipart/form-data" in rb)


def _client(role):
    c = TestClient(app, raise_server_exceptions=False)
    if role != "anon":
        assert login(c, ACCOUNTS[role]).status_code == 200
    return c


@pytest.mark.parametrize("role", ["anon", "employee", "analyst", "secadmin", "admin"])
def test_no_operation_returns_a_server_error(role):
    spec, rng = _spec(), random.Random(42)
    client = _client(role)
    failures, sent = [], 0
    for (method, path, op), mode in itertools.product(list(operations()), ["valid", "empty", "wrongtype", "huge", "evil", "evil"]):
        url, query, body, multipart = build(path, op, spec, mode, rng)
        kwargs = {"params": query}
        if multipart:
            kwargs["files"] = {"file": ("fuzz.bin", b"\x00\x01MZ" * 50 if mode != "empty" else b"", "application/octet-stream")}
        elif body is not None:
            kwargs["json"] = {} if mode == "empty" else body
        if mode == "huge" and isinstance(kwargs.get("json"), dict):
            kwargs["json"] = {k: ("A" * 200000 if isinstance(v, str) else v) for k, v in kwargs["json"].items()}
        kwargs["params"] = {k: v[:1500] for k, v in kwargs["params"].items()}   # the HTTP client refuses oversized URLs itself
        try:
            res = client.request(method, url, **kwargs)
        except (httpx.InvalidURL, httpx.UnsupportedProtocol):
            continue
        sent += 1
        if res.status_code >= 500:
            failures.append(f"{role} {method} {url} [{mode}] -> {res.status_code} {res.text[:160]!r} body={str(kwargs.get('json'))[:140]}")
        if res.status_code == 401 and role != "anon":
            client = _client(role)            # a fuzzed call may have ended the session (e.g. deactivating the user): sign in again
    assert sent > 400
    assert not failures, f"{len(failures)} server errors:\n" + "\n".join(failures[:25])


def test_malformed_requests_never_crash_the_server():
    c = _client("admin")
    cases = [
        ("POST", f"{API}/incidents/INC-1/notes", {"content": b'{"note_text": ', "headers": {"Content-Type": "application/json"}}),
        ("POST", f"{API}/blocklist", {"content": b"\xff\xfe\x00garbage", "headers": {"Content-Type": "application/json"}}),
        ("POST", f"{API}/users", {"content": b"[1,2,3]", "headers": {"Content-Type": "application/json"}}),
        ("PUT", f"{API}/admin/settings", {"content": b'"just a string"', "headers": {"Content-Type": "application/json"}}),
        ("POST", f"{API}/soc/rules", {"content": b"{" * 5000, "headers": {"Content-Type": "application/json"}}),
        ("GET", f"{API}/incidents?limit=-5&offset=abc", {}),
        ("GET", f"{API}/events?limit=99999999999999999999", {}),
        ("POST", f"{API}/files/analyze", {"content": b"not multipart", "headers": {"Content-Type": "multipart/form-data; boundary=x"}}),
        ("GET", f"{API}/system/audit?limit=0&q=" + "%" * 90, {}),
    ]
    for method, url, kw in cases:
        res = c.request(method, url, **kw)
        assert res.status_code < 500, f"{method} {url} -> {res.status_code} {res.text[:200]}"
