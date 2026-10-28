"""In-memory stand-in for the Zetaris REST API, following https://api.saas.enterprise.zetaris.com/redoc/docs.yaml.

SQL is executed for real against SQLite (CAST(... AS TIMESTAMP) literals are rewritten to plain strings, and
timestamps are stored as 'YYYY-MM-DD HH:MM:SS' so they order correctly). That checks the queries' logic; it cannot
check Spark/Trino dialect differences, which need a live Zetaris instance.
"""
import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta

import httpx

ORG_ID = "4242"
API_KEY = "zk_test_key"
USER, PASSWORD, ID_TOKEN = "svc", "pw", "idtoken-1"


def ts(minutes_ago: int) -> str:
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")


ATTACKER = "45.155.205.233"


class FakeZetaris:
    def __init__(self) -> None:
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.cursors: dict = {}
        self.open_count = 0
        self.closed_count = 0
        self.requests: list = []
        self.valid_tokens = {API_KEY, ID_TOKEN}
        self.expire_id_token_once = False
        self.fail_next_start = None
        self._schema()

    def _schema(self) -> None:
        self.db.executescript("""
            CREATE TABLE auth_logs (event_id TEXT, event_time TEXT, username TEXT, src_ip TEXT, result TEXT);
            CREATE TABLE network_flows (flow_id TEXT, event_time TEXT, src_ip TEXT, dst_ip TEXT, dst_port INT,
                                        protocol TEXT, bytes INT, packets INT);
            CREATE TABLE email_logs (message_id TEXT, event_time TEXT, sender TEXT, recipient TEXT, subject TEXT, body TEXT);
        """)

    def add_auth(self, minutes_ago: int, user: str, ip: str, result: str) -> None:
        self.db.execute("INSERT INTO auth_logs VALUES (?,?,?,?,?)", (uuid.uuid4().hex, ts(minutes_ago), user, ip, result))

    def add_flow(self, minutes_ago: int, src: str, dst: str, port: int, nbytes: int = 400, packets: int = 3) -> None:
        self.db.execute("INSERT INTO network_flows VALUES (?,?,?,?,?,?,?,?)",
                        (uuid.uuid4().hex, ts(minutes_ago), src, dst, port, "TCP", nbytes, packets))

    def add_email(self, minutes_ago: int, mid: str, sender: str, rcpt: str, subject: str, body: str) -> None:
        self.db.execute("INSERT INTO email_logs VALUES (?,?,?,?,?,?)", (mid, ts(minutes_ago), sender, rcpt, subject, body))

    def seed_attack(self) -> None:
        for i in range(12):
            self.add_auth(50 - i, "jane.doe@corp.example", ATTACKER, "FAILURE")
        self.add_auth(30, "jane.doe@corp.example", ATTACKER, "SUCCESS")
        for i in range(2):
            self.add_auth(40 - i, "bob@corp.example", "198.18.5.5", "FAILURE")
        self.add_auth(20, "bob@corp.example", "198.18.5.5", "SUCCESS")
        for port in (21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080):
            self.add_flow(45, ATTACKER, "10.0.0.5", port, nbytes=200, packets=2)
        self.add_flow(10, "10.0.0.8", "93.184.216.34", 443, nbytes=1200, packets=8)
        self.add_email(60, "m-1", "it-support@micr0soft-verify.xyz", "jane.doe@corp.example",
                       "Urgent: verify your account now",
                       "Your account will be suspended. Click http://login-microsoft365-verify.xyz/auth to verify your password immediately.")
        self.add_email(55, "m-2", "carol@corp.example", "bob@corp.example", "Lunch on Friday?", "Are we still on for lunch on Friday at noon?")

    # --- HTTP layer ------------------------------------------------------------------------------------------------
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _json(self, code: int, body) -> httpx.Response:
        return httpx.Response(code, json=body)

    def _handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append((req.method, req.url.path))
        h = req.headers
        try:
            uuid.UUID(h.get("x-request-id", ""))
        except ValueError:
            return httpx.Response(400, text="Invalid value for: header X-Request-ID")
        if h.get("x-org-id") != ORG_ID:
            return httpx.Response(400, text="Invalid value for: header X-Org-ID")

        if req.url.path == "/api/v1.0/auth/login":
            import base64
            expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
            if h.get("authorization") != expected:
                return self._json(404, {"msg": "User not found"})
            return self._json(200, {"idToken": ID_TOKEN, "refreshToken": "refresh-1"})

        token = h.get("authorization", "").removeprefix("Bearer ")
        if token == ID_TOKEN and self.expire_id_token_once:
            self.expire_id_token_once = False
            return self._json(401, {"msg": "Token expired"})
        if token not in self.valid_tokens:
            return self._json(401, {"msg": "Invalid token"})

        path = req.url.path
        if path == "/api/v1.0/lightning-database/databases" and req.method == "GET":
            return self._json(200, [{"databaseId": 1, "name": "cybershield", "tableCount": 3}])
        if path == "/api/v1.0/query/sql/start" and req.method == "POST":
            if self.fail_next_start:
                code, msg = self.fail_next_start
                self.fail_next_start = None
                return self._json(code, {"msg": msg})
            body = json.loads(req.content)
            sql = re.sub(r"CAST\(('[^']*') AS TIMESTAMP\)", r"\1", body["select"])
            try:
                rows = [dict(r) for r in self.db.execute(sql).fetchall()]
            except sqlite3.Error as exc:
                return self._json(400, {"msg": f"SQL error: {exc}"})
            token_id = uuid.uuid4().hex
            self.cursors[token_id] = (rows, body["pageLimit"])
            self.open_count += 1
            return self._json(200, self._page(token_id, 0))
        if path == "/api/v1.0/query/sql/page" and req.method == "GET":
            q = req.url.params
            if q["queryToken"] not in self.cursors:
                return self._json(404, {"msg": "Unknown query token"})
            return self._json(200, self._page(q["queryToken"], int(q["pageNumber"])))
        if path.startswith("/api/v1.0/query/sql/close/") and req.method == "DELETE":
            if self.cursors.pop(path.rsplit("/", 1)[1], None) is not None:
                self.closed_count += 1
            return httpx.Response(200)
        return self._json(404, {"msg": "not found"})

    def _page(self, token: str, page: int) -> dict:
        rows, limit = self.cursors[token]
        total_pages = max(1, -(-len(rows) // limit))
        return {"records": rows[page * limit:(page + 1) * limit], "pageNumber": page, "pageLimit": limit,
                "totalCount": len(rows), "totalPages": total_pages, "queryToken": token}
