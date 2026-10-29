"""OpenID Connect sign-in against a fake identity provider that signs real RS256 / ES256 tokens."""
import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from app.config import settings
from app.models import AuditLog, User
from app.services import oidc
from tests.conftest import ACCOUNTS, make_client

API = "/api/v1"
ISSUER = "https://idp.example.org"
CLIENT_ID = "cybershield-client"


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def int_b64(n: int) -> str:
    return b64e(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class FakeIdP:
    def __init__(self):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.claims_override, self.sign_with, self.alg, self.token_status = {}, "rsa", "RS256", 200
        self.seen_token_request, self.codes = None, {}
        self.jwks_fetches = 0

    def jwks(self):
        pub = self.rsa.public_key().public_numbers()
        e = self.ec.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256", "n": int_b64(pub.n), "e": int_b64(pub.e)},
                         {"kty": "EC", "kid": "ec1", "use": "sig", "crv": "P-256", "x": int_b64(e.x), "y": int_b64(e.y)}]}

    def make_token(self, nonce, **claims):
        body = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u-1", "email": ACCOUNTS["analyst"], "email_verified": True,
                "nonce": nonce, "iat": int(time.time()), "exp": int(time.time()) + 300}
        body.update(self.claims_override)
        body.update(claims)
        alg = self.alg
        header = {"alg": alg, "typ": "JWT", "kid": "ec1" if alg == "ES256" else "rsa1"}
        signing = f"{b64e(json.dumps(header).encode())}.{b64e(json.dumps(body).encode())}"
        if alg == "none":
            return signing + "."
        if alg == "HS256":
            import hmac
            return signing + "." + b64e(hmac.new(b"anything", signing.encode(), hashlib.sha256).digest())
        if alg == "ES256":
            der = self.ec.sign(signing.encode(), ec.ECDSA(hashes.SHA256()))
            r, s = utils.decode_dss_signature(der)
            return signing + "." + b64e(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        key = self.other if self.sign_with == "other" else self.rsa
        return signing + "." + b64e(key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                                             "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"})
        if path == "/jwks":
            self.jwks_fetches += 1
            return httpx.Response(200, json=self.jwks())
        if path == "/token":
            form = parse_qs(request.content.decode())
            self.seen_token_request = {k: v[0] for k, v in form.items()}
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            nonce = self.codes.get(form["code"][0])
            return httpx.Response(200, json={"id_token": self.make_token(nonce), "access_token": "x", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(oidc, "_transport", httpx.MockTransport(fake.handler))
    oidc.reset_cache()
    for name, value in (("OIDC_ISSUER", ISSUER), ("OIDC_CLIENT_ID", CLIENT_ID), ("OIDC_CLIENT_SECRET", "shh"),
                        ("OIDC_ALLOWED_EMAIL_DOMAINS", ""), ("OIDC_IDP_ENFORCES_MFA", False), ("OIDC_EMAIL_CLAIM", "email")):
        monkeypatch.setattr(settings, name, value)
    yield fake
    oidc.reset_cache()


def start(client, idp):
    """Begin sign-in; return (authorize query params). The provider 'remembers' the nonce for the code it will issue."""
    r = client.get(f"{API}/auth/sso/login", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(f"{ISSUER}/authorize?"), r.text
    q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
    idp.codes["code-1"] = q["nonce"]
    return q


def finish(client, q, code="code-1", state=None):
    return client.get(f"{API}/auth/sso/callback", params={"code": code, "state": state or q["state"]}, follow_redirects=False)


def signed_in(client) -> bool:
    return client.get(f"{API}/auth/me").status_code == 200


def last_audit(db, action):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.id.desc()).first()


def test_sso_is_off_by_default():
    with make_client() as c:
        assert c.get(f"{API}/auth/sso/config").json()["enabled"] is False
        assert c.get(f"{API}/auth/sso/login", follow_redirects=False).status_code == 404
        assert c.get(f"{API}/auth/sso/callback", follow_redirects=False).status_code == 404


def test_full_flow_signs_an_existing_user_in(idp, db):
    with make_client() as c:
        assert c.get(f"{API}/auth/sso/config").json()["enabled"] is True
        q = start(c, idp)
        assert q["code_challenge_method"] == "S256" and q["response_type"] == "code" and q["client_id"] == CLIENT_ID
        r = finish(c, q)
        assert r.status_code == 303 and r.headers["location"] == "/"
        assert signed_in(c)
        # PKCE: the provider received a verifier that hashes to the challenge it was sent
        verifier = idp.seen_token_request["code_verifier"]
        assert b64e(hashlib.sha256(verifier.encode()).digest()) == q["code_challenge"]
        assert idp.seen_token_request["redirect_uri"].endswith("/api/v1/auth/sso/callback")
    assert last_audit(db, "AUTH_SSO_SUCCESS").actor == ACCOUNTS["analyst"]


def test_es256_tokens_are_accepted(idp):
    idp.alg = "ES256"
    with make_client() as c:
        finish(c, start(c, idp))
        assert signed_in(c)


@pytest.mark.parametrize("override,why", [
    ({"aud": "someone-else"}, "audience"), ({"iss": "https://evil.example"}, "issuer"), ({"exp": int(time.time()) - 3600}, "expired"),
    ({"nonce": "not-mine"}, "nonce"), ({"email_verified": False}, "unverified email"), ({"email": "stranger@example.org"}, "unknown user"),
    ({"email": ""}, "no email"), ({"sub": ""}, "no subject"), ({"aud": [CLIENT_ID, "x"], "azp": "x"}, "azp"),
    ({"iat": int(time.time()) + 3600}, "from the future"),
])
def test_bad_tokens_do_not_sign_anyone_in(idp, db, override, why):
    idp.claims_override = override
    with make_client() as c:
        r = finish(c, start(c, idp))
        assert r.status_code == 303 and r.headers["location"] == "/?sso_error=denied", why
        assert not signed_in(c), why
    assert last_audit(db, "AUTH_SSO_DENIED") is not None


def test_token_signed_by_another_key_is_refused(idp):
    idp.sign_with = "other"
    with make_client() as c:
        assert finish(c, start(c, idp)).headers["location"].endswith("sso_error=denied")
        assert not signed_in(c)


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_unsafe_algorithms_are_refused(idp, alg):
    idp.alg = alg
    with make_client() as c:
        assert finish(c, start(c, idp)).headers["location"].endswith("sso_error=denied")
        assert not signed_in(c)


def test_state_mismatch_and_missing_cookie_are_refused(idp):
    with make_client() as c:
        q = start(c, idp)
        assert finish(c, q, state="forged").headers["location"].endswith("sso_error=denied")
        assert not signed_in(c)
    with make_client() as other:                       # a callback with no transaction cookie (e.g. login CSRF)
        assert finish(other, q).headers["location"].endswith("sso_error=denied")
        assert not signed_in(other)


def test_the_transaction_is_single_use(idp):
    with make_client() as c:
        q = start(c, idp)
        assert finish(c, q).headers["location"] == "/"
        c.cookies.clear()
        assert finish(c, q).headers["location"].endswith("sso_error=denied")


def test_tampered_transaction_cookie_is_refused(idp):
    with make_client() as c:
        q = start(c, idp)
        value = c.cookies.get("cs_sso")
        c.cookies.set("cs_sso", value[:-3] + ("aaa" if not value.endswith("aaa") else "bbb"), domain="testserver.local", path="/")
        assert finish(c, q).headers["location"].endswith("sso_error=denied")


def test_provider_errors_and_token_failures_are_refused(idp):
    idp.token_status = 400
    with make_client() as c:
        assert finish(c, start(c, idp)).headers["location"].endswith("sso_error=denied")
        r = c.get(f"{API}/auth/sso/callback", params={"error": "access_denied"}, follow_redirects=False)
        assert r.headers["location"].endswith("sso_error=denied")


def test_sso_never_creates_accounts(idp, db):
    idp.claims_override = {"email": "brand.new@example.org"}
    with make_client() as c:
        finish(c, start(c, idp))
    assert db.query(User).filter(User.email == "brand.new@example.org").count() == 0


def test_deactivated_and_locked_users_cannot_use_sso(idp, db):
    from datetime import timedelta
    from app.models import naive_utc_now
    user = db.query(User).filter(User.email == ACCOUNTS["analyst"]).one()
    try:
        user.is_active = False
        db.commit()
        with make_client() as c:
            finish(c, start(c, idp))
            assert not signed_in(c)
        user.is_active, user.locked_until = True, naive_utc_now() + timedelta(minutes=5)
        db.commit()
        with make_client() as c:
            finish(c, start(c, idp))
            assert not signed_in(c)
    finally:
        user.is_active, user.locked_until = True, None
        db.commit()


def test_email_domain_allow_list(idp, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ALLOWED_EMAIL_DOMAINS", "other-company.com")
    with make_client() as c:
        finish(c, start(c, idp))
        assert not signed_in(c)


def test_mfa_still_applies_unless_the_idp_is_trusted_to_do_it(idp, db, monkeypatch):
    monkeypatch.setattr(settings, "MFA_ENFORCED", True)
    with make_client() as c:
        finish(c, start(c, idp))
        assert c.get(f"{API}/auth/me").json()["mfa_state"] in ("enroll", "verify")
    monkeypatch.setattr(settings, "OIDC_IDP_ENFORCES_MFA", True)
    with make_client() as c:
        finish(c, start(c, idp))
        assert c.get(f"{API}/auth/me").json()["mfa_state"] == "ok"


def test_rotated_signing_key_is_picked_up(idp):
    with make_client() as c:
        finish(c, start(c, idp))                       # warm the key cache
        assert signed_in(c)
    old = idp.rsa
    idp.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)      # provider rotates its key
    with make_client() as c:
        finish(c, start(c, idp))
        assert signed_in(c)
    assert old is not idp.rsa and idp.jwks_fetches >= 2


def test_discovery_with_a_different_issuer_is_refused(idp, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example.org/tenant")
    with make_client() as c:
        assert c.get(f"{API}/auth/sso/login", follow_redirects=False).headers["location"].endswith("sso_error=denied")
