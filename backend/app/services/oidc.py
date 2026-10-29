"""OpenID Connect sign-in: authorization-code flow with PKCE, ID token verified against the provider's published keys.

Deliberately small and strict:
  * only RS256 and ES256 ID tokens are accepted (never "none", never HMAC with a public key as the secret);
  * issuer, audience, expiry, nonce and (when several audiences) azp are all checked;
  * the person must already exist in CyberShield and be active: SSO never creates an account or changes a role.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from app.config import settings
from app.utils.crypto import hmac_hex

LEEWAY_SECONDS = 60
CACHE_SECONDS = 3600
TXN_SECONDS = 600
ALLOWED_ALGS = {"RS256", "ES256"}

_transport: Optional[httpx.BaseTransport] = None        # tests inject a fake provider here
_cache: Dict[str, Any] = {"discovery": None, "discovery_at": 0.0, "jwks": None, "jwks_at": 0.0}


class OidcError(Exception):
    """Sign-in refused. The message is for the audit log, never shown to the user."""


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _client() -> httpx.Client:
    return httpx.Client(timeout=10, transport=_transport, follow_redirects=False)


def _require_https(url: str, what: str) -> None:
    if not url.startswith("https://") and not settings.is_development:
        raise OidcError(f"{what} must use https")


def reset_cache() -> None:
    _cache.update(discovery=None, discovery_at=0.0, jwks=None, jwks_at=0.0)


def discovery() -> Dict[str, Any]:
    if _cache["discovery"] and time.time() - _cache["discovery_at"] < CACHE_SECONDS:
        return _cache["discovery"]
    issuer = (settings.OIDC_ISSUER or "").rstrip("/")
    _require_https(issuer, "OIDC_ISSUER")
    with _client() as c:
        r = c.get(f"{issuer}/.well-known/openid-configuration")
    if r.status_code != 200:
        raise OidcError(f"discovery answered {r.status_code}")
    doc = r.json()
    if str(doc.get("issuer", "")).rstrip("/") != issuer:
        raise OidcError("discovery document issuer does not match OIDC_ISSUER")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(key):
            raise OidcError(f"discovery document lacks {key}")
        _require_https(doc[key], key)
    _cache.update(discovery=doc, discovery_at=time.time())
    return doc


def _jwks(force: bool = False) -> Dict[str, Any]:
    if not force and _cache["jwks"] and time.time() - _cache["jwks_at"] < CACHE_SECONDS:
        return _cache["jwks"]
    with _client() as c:
        r = c.get(discovery()["jwks_uri"])
    if r.status_code != 200:
        raise OidcError(f"jwks answered {r.status_code}")
    _cache.update(jwks=r.json(), jwks_at=time.time())
    return _cache["jwks"]


# ------------------------------------------------------------------------------------- transaction cookie

def new_transaction() -> Tuple[str, str, str, str]:
    """(state, nonce, code_verifier, signed cookie value). The cookie carries what the callback must match."""
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    body = _b64e(json.dumps({"s": state, "n": nonce, "v": verifier, "x": int(time.time()) + TXN_SECONDS}).encode())
    return state, nonce, verifier, f"{body}.{hmac_hex('oidc-txn-v1', body)}"


def open_transaction(cookie: str) -> Dict[str, Any]:
    body, _, mac = (cookie or "").partition(".")
    if not body or not hmac.compare_digest(mac, hmac_hex("oidc-txn-v1", body)):
        raise OidcError("sign-in transaction cookie missing or tampered")
    try:
        data = json.loads(_b64d(body))
    except ValueError:
        raise OidcError("sign-in transaction cookie unreadable")
    if int(data.get("x", 0)) < time.time():
        raise OidcError("sign-in transaction expired")
    return data


def authorization_url(state: str, nonce: str, verifier: str) -> str:
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    query = urlencode({
        "response_type": "code", "client_id": settings.OIDC_CLIENT_ID, "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.OIDC_SCOPES, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    return f"{discovery()['authorization_endpoint']}?{query}"


def exchange_code(code: str, verifier: str) -> Dict[str, Any]:
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.OIDC_CLIENT_ID, "code_verifier": verifier}
    if settings.OIDC_CLIENT_SECRET:
        data["client_secret"] = settings.OIDC_CLIENT_SECRET
    with _client() as c:
        r = c.post(discovery()["token_endpoint"], data=data, headers={"Accept": "application/json"})
    if r.status_code != 200:
        raise OidcError(f"token endpoint answered {r.status_code}")
    body = r.json()
    if not body.get("id_token"):
        raise OidcError("token response has no id_token")
    return body


# ------------------------------------------------------------------------------------------- ID token

def _public_key(jwk: Dict[str, Any]):
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(int.from_bytes(_b64d(jwk["e"]), "big"), int.from_bytes(_b64d(jwk["n"]), "big")).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"), ec.SECP256R1()).public_key()
    raise OidcError("unsupported key type")


def _verify_signature(alg: str, kid: Optional[str], signing_input: bytes, signature: bytes) -> None:
    for attempt in (False, True):                                    # a rotated key: refetch once
        keys = [k for k in _jwks(force=attempt).get("keys", []) if (kid is None or k.get("kid") == kid) and k.get("use", "sig") == "sig"]
        for jwk in keys:
            try:
                key = _public_key(jwk)
                if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
                    key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
                    return
                if alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey) and len(signature) == 64:
                    key.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                               signing_input, ec.ECDSA(hashes.SHA256()))
                    return
            except (InvalidSignature, ValueError, KeyError):
                continue
    raise OidcError("ID token signature does not verify")


def verify_id_token(token: str, nonce: str, now: Optional[float] = None) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcError("ID token is not a signed JWT")
    try:
        header, claims = json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1]))
        signature = _b64d(parts[2])
    except ValueError:
        raise OidcError("ID token is not decodable")
    if header.get("alg") not in ALLOWED_ALGS:
        raise OidcError(f"ID token algorithm {header.get('alg')!r} is not accepted")
    _verify_signature(header["alg"], header.get("kid"), f"{parts[0]}.{parts[1]}".encode(), signature)

    t = now if now is not None else time.time()
    if str(claims.get("iss", "")).rstrip("/") != (settings.OIDC_ISSUER or "").rstrip("/"):
        raise OidcError("issuer mismatch")
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if settings.OIDC_CLIENT_ID not in audiences:
        raise OidcError("audience mismatch")
    if len(audiences) > 1 and claims.get("azp") != settings.OIDC_CLIENT_ID:
        raise OidcError("authorized party mismatch")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < t - LEEWAY_SECONDS:
        raise OidcError("ID token expired")
    if isinstance(claims.get("iat"), (int, float)) and claims["iat"] > t + LEEWAY_SECONDS:
        raise OidcError("ID token issued in the future")
    if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > t + LEEWAY_SECONDS:
        raise OidcError("ID token not yet valid")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("nonce mismatch")
    if not claims.get("sub"):
        raise OidcError("no subject")
    return claims


def email_from(claims: Dict[str, Any]) -> str:
    email = str(claims.get(settings.OIDC_EMAIL_CLAIM) or "").strip().lower()
    if not email or "@" not in email:
        raise OidcError(f"ID token has no usable {settings.OIDC_EMAIL_CLAIM} claim")
    if claims.get("email_verified") is False or str(claims.get("email_verified")).lower() == "false":
        raise OidcError("provider says the email address is not verified")
    allowed = [d.strip().lower() for d in settings.OIDC_ALLOWED_EMAIL_DOMAINS.split(",") if d.strip()]
    if allowed and email.rsplit("@", 1)[1] not in allowed:
        raise OidcError("email domain is not allowed")
    return email
