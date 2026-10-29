# Single sign-on (OpenID Connect)

Staff can sign in through your identity provider (Microsoft Entra ID, Okta, Google Workspace, Keycloak, Auth0, anything
that speaks OpenID Connect) instead of a CyberShield password.

What it does and does not do:

- Authorization-code flow with **PKCE (S256)**, `state` and `nonce`. The transaction lives in a short-lived, signed,
  HttpOnly cookie, so a callback without a matching start is refused.
- The ID token must be signed **RS256 or ES256** with a key from the provider's published keys (refetched once if the
  provider rotated them). `none`, HMAC and unknown algorithms are refused. Issuer, audience (and `azp` when there are
  several), expiry, issue time and nonce are all checked.
- **No auto-provisioning.** The email in the token must belong to an existing, active, unlocked CyberShield user.
  Anyone else is refused and the attempt is audited (`AUTH_SSO_DENIED`). Roles are never taken from the token: an
  administrator still creates the account and assigns the role.
- **Two-step verification:** unless `OIDC_IDP_ENFORCES_MFA=true`, an SSO session of a privileged user still has to pass
  CyberShield's own TOTP step. Set it to `true` only when your provider enforces MFA for this application.
- Success and every refusal are written to the audit log. The user only ever sees "refused"; the reason is in the log.
- Password sign-in stays available. To make SSO the only way in for someone, deactivate their password (not yet a
  setting; say if you need it).

## Set up

1. In your provider, register a **web application** with redirect URI
   `https://<your host>/api/v1/auth/sso/callback` and the scopes `openid email profile`.
2. Set (see `.env.example`):

```
OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0     # the value of "issuer" in <issuer>/.well-known/openid-configuration
OIDC_CLIENT_ID=<application id>
OIDC_CLIENT_SECRET=<client secret>        # optional only for providers that allow public PKCE clients
OIDC_PROVIDER_NAME=Microsoft              # label on the button
OIDC_ALLOWED_EMAIL_DOMAINS=company.com    # optional extra restriction
OIDC_EMAIL_CLAIM=email                    # use preferred_username if your provider omits "email"
PUBLIC_BASE_URL=https://<your host>       # used to build the redirect URI (or set OIDC_REDIRECT_URI)
```

3. The login page shows **Continue with <provider>** when `OIDC_ISSUER` and `OIDC_CLIENT_ID` are set.

If the provider sends `email_verified: false`, the sign-in is refused. Providers that omit the claim (Entra ID does) are
accepted; combine with `OIDC_ALLOWED_EMAIL_DOMAINS` if you want a tighter rule.

## Tested with

An in-process fake provider that signs real RS256 and ES256 tokens (`backend/tests/test_sso.py`, 26 tests: happy path,
PKCE, wrong audience/issuer/nonce/expiry/state, forged and `none`/HMAC tokens, unknown and deactivated users, MFA
handling, key rotation, tampered cookie). **It has not been run against a live Entra ID/Okta tenant**; do one real
sign-in against your provider before relying on it.
