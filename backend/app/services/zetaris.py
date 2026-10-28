"""Client for the Zetaris REST API (OpenAPI spec: https://api.saas.enterprise.zetaris.com/redoc/docs.yaml).

Zetaris queries data where it lives, so CyberShield never copies your log stores. This module only talks to it
server-side: credentials stay in the environment and the browser never sees them.

Flow (per the published spec):
  GET    /api/v1.0/auth/login          Basic user/password + X-Org-ID  ->  {idToken, refreshToken}
  POST   /api/v1.0/query/sql/start     {select, pageLimit<=100}        ->  first page + queryToken
  GET    /api/v1.0/query/sql/page      queryToken, pageLimit, pageNumber
  DELETE /api/v1.0/query/sql/close/{queryToken}
Every call carries X-Request-ID (uuid) and X-Org-ID, and `Authorization: Bearer <API key or idToken>`.
"""
import json
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings

logger = logging.getLogger("cybershield.zetaris")

MAX_PAGE = 100


class ZetarisError(Exception):
    """Raised for any Zetaris failure. Messages never contain credentials."""


class ZetarisNotConfigured(ZetarisError):
    pass


# --- SQL safety ------------------------------------------------------------------------------------------------
# The query API takes a raw SQL string with no bind parameters, so every value we embed is whitelisted and
# every statement is checked to be a single read-only SELECT.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9@._:+\-]{1,128}$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,2}$")
_STRING_LITERAL = re.compile(r"'[^']*'")
_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|merge|grant|revoke|call|exec|execute|copy|replace|set|use|"
    r"load|export|attach)\b", re.I)


def sql_value(value: str) -> str:
    """A string literal for a value that matches a strict whitelist; anything else is refused."""
    if not isinstance(value, str) or not _SAFE_VALUE.match(value):
        raise ValueError("Value contains characters that are not allowed in a query.")
    return f"'{value}'"


def sql_ident(name: str) -> str:
    if not _IDENT.match(name or ""):
        raise ValueError(f"Invalid column name: {name!r}")
    return name


def sql_table(name: Optional[str]) -> str:
    if not name or not _TABLE.match(name):
        raise ValueError(f"Invalid table name: {name!r}")
    return name


def sql_timestamp(dt) -> str:
    return f"CAST('{dt.strftime('%Y-%m-%d %H:%M:%S')}' AS TIMESTAMP)"


def assert_read_only(sql: str) -> str:
    text = sql.strip().rstrip(";").strip()
    if ";" in _STRING_LITERAL.sub("''", text):
        raise ValueError("Only a single statement is allowed.")
    if not re.match(r"^(select|with)\b", text, re.I):
        raise ValueError("Only SELECT queries are allowed.")
    if _FORBIDDEN.search(_STRING_LITERAL.sub("''", text)):
        raise ValueError("Only read-only queries are allowed.")
    return text


# --- Client -------------------------------------------------------------------------------------------------------
class ZetarisClient:
    def __init__(self, base_url: Optional[str] = None, org_id: Optional[int] = None, api_key: Optional[str] = None,
                 username: Optional[str] = None, password: Optional[str] = None, *,
                 transport: Optional[httpx.BaseTransport] = None, timeout: float = 30.0) -> None:
        self.base_url = (base_url or settings.ZETARIS_BASE_URL).rstrip("/")
        self.org_id = org_id if org_id is not None else settings.ZETARIS_ORG_ID
        self.api_key = api_key if api_key is not None else settings.ZETARIS_API_KEY
        self.username = username if username is not None else settings.ZETARIS_USERNAME
        self.password = password if password is not None else settings.ZETARIS_PASSWORD
        if self.org_id is None or not (self.api_key or (self.username and self.password)):
            raise ZetarisNotConfigured("Zetaris is not configured: set ZETARIS_ORG_ID and ZETARIS_API_KEY "
                                       "(or ZETARIS_USERNAME and ZETARIS_PASSWORD).")
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)
        self._id_token: Optional[str] = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ZetarisClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- auth ---------------------------------------------------------------------------------------------------
    def _base_headers(self) -> Dict[str, str]:
        return {"X-Request-ID": str(uuid.uuid4()), "X-Org-ID": str(self.org_id)}

    def login(self) -> str:
        if not (self.username and self.password):
            raise ZetarisError("No username/password configured to log in with.")
        try:
            resp = self._http.get("/api/v1.0/auth/login", headers=self._base_headers(),
                                  auth=(self.username, self.password))
        except httpx.HTTPError as exc:
            raise ZetarisError(f"Could not reach Zetaris: {type(exc).__name__}") from exc
        self._raise_for(resp)
        self._id_token = resp.json()["idToken"]
        return self._id_token

    def _bearer(self) -> str:
        if self.api_key:
            return self.api_key
        return self._id_token or self.login()

    # -- plumbing -----------------------------------------------------------------------------------------------
    @staticmethod
    def _raise_for(resp: httpx.Response) -> None:
        if resp.status_code < 400:
            return
        msg = ""
        try:
            msg = resp.json().get("msg", "")
        except Exception:
            msg = resp.text[:200]
        raise ZetarisError(f"Zetaris returned HTTP {resp.status_code}: {msg}".strip())

    def _call(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        last: Optional[Exception] = None
        for attempt in (1, 2):
            headers = {**self._base_headers(), "Authorization": f"Bearer {self._bearer()}"}
            try:
                resp = self._http.request(method, path, headers=headers, **kwargs)
            except httpx.HTTPError as exc:  # network trouble: one retry
                last = ZetarisError(f"Could not reach Zetaris: {type(exc).__name__}")
                time.sleep(0.2)
                continue
            if resp.status_code == 401 and not self.api_key and attempt == 1:
                self._id_token = None  # idToken expired: log in again
                continue
            if resp.status_code >= 500 and attempt == 1:
                last = ZetarisError(f"Zetaris returned HTTP {resp.status_code}")
                time.sleep(0.2)
                continue
            self._raise_for(resp)
            return resp
        raise last or ZetarisError("Zetaris request failed.")

    # -- API ----------------------------------------------------------------------------------------------------
    @staticmethod
    def _records(raw: Optional[List[Any]]) -> List[Dict[str, Any]]:
        out = []
        for item in raw or []:
            out.append(json.loads(item) if isinstance(item, str) else item)
        return out

    def query(self, sql: str, *, page_limit: int = MAX_PAGE, max_rows: int = 5000) -> List[Dict[str, Any]]:
        """Runs a read-only SELECT and returns up to max_rows records, closing the server-side cursor."""
        statement = assert_read_only(sql)
        page_limit = max(1, min(page_limit, MAX_PAGE))
        resp = self._call("POST", "/api/v1.0/query/sql/start", json={"select": statement, "pageLimit": page_limit})
        first = resp.json()
        token = first["queryToken"]
        try:
            rows = self._records(first.get("records"))
            first_page, total_pages = int(first.get("pageNumber", 0)), int(first.get("totalPages", 1))
            for page in range(first_page + 1, first_page + total_pages):
                if len(rows) >= max_rows:
                    break
                nxt = self._call("GET", "/api/v1.0/query/sql/page",
                                 params={"queryToken": token, "pageLimit": page_limit, "pageNumber": page}).json()
                rows.extend(self._records(nxt.get("records")))
            return rows[:max_rows]
        finally:
            try:
                self._call("DELETE", f"/api/v1.0/query/sql/close/{token}")
            except ZetarisError:
                logger.warning("Could not close Zetaris query cursor.")

    def list_databases(self) -> List[Dict[str, Any]]:
        return self._call("GET", "/api/v1.0/lightning-database/databases").json()

    def ping(self) -> Dict[str, Any]:
        """A real round trip: authenticates and lists databases. Used for the honest 'Connected' status."""
        started = time.monotonic()
        databases = self.list_databases()
        return {"latency_ms": int((time.monotonic() - started) * 1000), "databases": databases}


def get_client() -> ZetarisClient:
    return ZetarisClient()
