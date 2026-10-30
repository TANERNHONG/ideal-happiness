"""Single sign-on (OpenID Connect) for the actions that change data.

Reading, analysing, reviewing and querying work without signing in, as before.
Adding a dataset, importing its archives into the pipeline, and training models
need a signed-in user with the admin role, because they change the data the
whole console relies on.

SSO is OFF until an administrator configures it in ``var/auth.json`` on the
laptop (see ``docs/user/03_sso_and_datasets.md`` and ``auth.example.json``). The
file is read from disk only: nothing in the browser can switch SSO on or change
who is an admin.

Flow: OpenID Connect authorization code with PKCE (S256), state and nonce, built
on maintained libraries rather than hand-written protocol code:

* Authlib's requests client builds the sign-in link (with the PKCE challenge)
  and exchanges the code for tokens, over TLS with certificates verified;
* joserfc, Authlib's JOSE library, checks the ID token: its signature against
  the provider's published keys (fetched again once if the provider has rotated
  them), then issuer, audience, authorised party, expiry, issue time and nonce.
  Only asymmetric signing algorithms are accepted.

Versions are pinned in ``requirements.txt``. Sessions live in memory (signing in
again after a restart) behind an HttpOnly, SameSite=Lax cookie.

The laptop is shared, so sign-in asks the provider for its account picker
(``prompt``, default ``select_account``; ``login`` asks for the password every
time), and signing out also ends the provider's session when it offers an
``end_session_endpoint`` (OpenID Connect RP-Initiated Logout). Otherwise the
next person to press "Sign in" could be signed straight back in as the previous
admin. ``python -m service.sso_check`` checks the settings without signing in.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

import requests
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt
from joserfc.errors import BadSignatureError, ExpiredTokenError, InvalidClaimError, InvalidKeyIdError, JoseError, MissingClaimError
from joserfc.jwk import KeySet

from .config import VAR

AUTH_FILE = VAR / "auth.json"
COOKIE = "otc_session"
PENDING_SECONDS = 600
TIMEOUT = 15                              # seconds for any call to the provider
CLOCK_LEEWAY = 120                        # seconds of clock difference allowed on expiry and issue time
# Asymmetric algorithms only: never "none", and never HS*, which would let anyone holding the client secret mint tokens.
SIGNING_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
CLAIM_PROBLEMS = {
    "iss": "The ID token came from an unexpected issuer.",
    "aud": "The ID token was not issued for this console.",
    "azp": "The ID token was not issued for this console.",
    "nonce": "The sign-in answer did not match this attempt.",
    "exp": "The ID token has expired.",
    "iat": "The ID token's issue time is missing or in the future.",
    "sub": "The ID token does not say who signed in.",
}
_lock = threading.Lock()
_pending: dict[str, dict] = {}            # state -> {nonce, verifier, created}
_sessions: dict[str, "User"] = {}         # session id -> user
_discovery: dict[str, dict] = {}          # issuer -> provider metadata
_keys: dict[str, KeySet] = {}             # jwks_uri -> the provider's public keys
_local = threading.local()                # the current request's user (set by the server per request)


@dataclass
class User:
    subject: str
    name: str
    email: str
    roles: list[str] = field(default_factory=list)
    admin: bool = False
    expires: float = 0.0
    id_token: str = field(default="", repr=False)      # kept only to tell the provider who is signing out


PROMPTS = ("", "select_account", "login")


def config() -> dict:
    try:
        stored = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stored = {}
    return {"mode": "off", "issuer": "", "client_id": "", "client_secret_env": "",
            "redirect_uri": "http://localhost:8765/auth/callback", "scopes": "openid profile email",
            "admin_claim": "roles", "admin_values": [], "session_hours": 8,
            "prompt": "select_account", "post_logout_redirect_uri": "", **stored}


def enabled() -> bool:
    c = config()
    return c["mode"] == "oidc" and bool(c["issuer"]) and bool(c["client_id"])


# --- per-request user -------------------------------------------------------------------

def bind(cookie_header: str | None) -> None:
    """Called by the server at the start of each request: find the session from the cookie."""
    _local.user = None
    if not cookie_header or not enabled():
        return
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            with _lock:
                user = _sessions.get(value)
                if user and user.expires > time.time():
                    _local.user = user
                elif user:
                    _sessions.pop(value, None)


def current() -> User | None:
    return getattr(_local, "user", None)


def require_admin() -> User:
    """Raise PermissionError unless a signed-in admin is making this request."""
    if not enabled():
        raise PermissionError("This needs single sign-on (SSO), which is not set up on this laptop yet. "
                              "An administrator turns it on in var/auth.json - see Documentation.")
    user = current()
    if user is None:
        raise PermissionError("Sign in with SSO first.")
    if not user.admin:
        raise PermissionError(f"Signed in as {user.name}, but this needs the admin role.")
    return user


def status() -> dict:
    user = current()
    return {"mode": "oidc" if enabled() else "off",
            "signed_in": user is not None,
            "user": {"name": user.name, "email": user.email, "admin": user.admin} if user else None,
            "admin": bool(user and user.admin),
            "login_url": "/auth/login" if enabled() else None}


# --- the provider ------------------------------------------------------------------------

def _https(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
        raise PermissionError("The SSO provider must be reached over https.")


def _get_json(url: str) -> dict:
    _https(url)
    try:
        response = requests.get(url, timeout=TIMEOUT, headers={"Accept": "application/json"})   # certificates verified
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as error:
        raise PermissionError(f"Could not reach the SSO provider ({url}): {error}") from error


def _metadata(issuer: str) -> dict:
    """The provider's discovery document, checked to belong to the configured issuer (OIDC Discovery 4.3)."""
    if issuer not in _discovery:
        meta = _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
        if str(meta.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
            raise PermissionError("The SSO provider's settings name a different issuer than var/auth.json.")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not meta.get(key):
                raise PermissionError(f"The SSO provider's settings have no {key}.")
            _https(meta[key])
        _discovery[issuer] = meta
    return _discovery[issuer]


def _key_set(meta: dict, refresh: bool = False) -> KeySet:
    uri = meta["jwks_uri"]
    if refresh or uri not in _keys:
        try:
            _keys[uri] = KeySet.import_key_set(_get_json(uri))
        except (JoseError, ValueError, TypeError) as error:
            raise PermissionError("The SSO provider's signing keys could not be read.") from error
    return _keys[uri]


def _client(c: dict) -> OAuth2Session:
    secret = os.environ.get(c["client_secret_env"]) if c["client_secret_env"] else None
    return OAuth2Session(client_id=c["client_id"], client_secret=secret, scope=c["scopes"],
                         redirect_uri=c["redirect_uri"], code_challenge_method="S256",
                         token_endpoint_auth_method="client_secret_post" if secret else "none",
                         default_timeout=TIMEOUT)


# --- sign-in -----------------------------------------------------------------------------

def login_redirect() -> str:
    """URL of the provider's sign-in page, with state, nonce and a PKCE challenge."""
    if not enabled():
        raise PermissionError("SSO is not set up on this laptop.")
    c = config()
    meta = _metadata(c["issuer"])
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    with _lock:
        now = time.time()
        for key in [k for k, v in _pending.items() if now - v["created"] > PENDING_SECONDS]:
            _pending.pop(key, None)
        _pending[state] = {"nonce": nonce, "verifier": verifier, "created": now}
    extra = {"prompt": c["prompt"]} if c["prompt"] in PROMPTS[1:] else {}       # shared laptop: never silent
    with _client(c) as client:
        url, _ = client.create_authorization_url(meta["authorization_endpoint"], state=state,
                                                 code_verifier=verifier, nonce=nonce, **extra)
    return url


def _verify_id_token(id_token: str, meta: dict, c: dict, nonce: str) -> dict:
    """Signature first (against the provider's keys), then the claims; any failure refuses the sign-in."""
    offered = meta.get("id_token_signing_alg_values_supported") or ["RS256"]
    algorithms = [a for a in offered if a in SIGNING_ALGORITHMS] or ["RS256"]
    try:
        try:
            token = jwt.decode(id_token, _key_set(meta), algorithms=algorithms)
        except InvalidKeyIdError:                    # the provider rotated its keys since they were fetched
            token = jwt.decode(id_token, _key_set(meta, refresh=True), algorithms=algorithms)
        jwt.JWTClaimsRegistry(
            leeway=CLOCK_LEEWAY,
            iss={"essential": True, "value": meta["issuer"]},
            aud={"essential": True, "value": c["client_id"]},
            sub={"essential": True}, exp={"essential": True}, iat={"essential": True},
            nonce={"essential": True, "value": nonce},
        ).validate(token.claims)
    except BadSignatureError as error:
        raise PermissionError("The ID token's signature did not match the SSO provider's keys.") from error
    except (ExpiredTokenError, InvalidClaimError, MissingClaimError) as error:
        raise PermissionError(CLAIM_PROBLEMS.get(error.claim, f"The ID token's {error.claim!r} claim was not acceptable.")) from error
    except (JoseError, ValueError) as error:
        raise PermissionError("The sign-in answer was not a valid, signed ID token.") from error
    claims = dict(token.claims)
    # With several audiences, the token must also name this console as the party it was issued to.
    audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if (len(audiences) > 1 or "azp" in claims) and claims.get("azp") != c["client_id"]:
        raise PermissionError(CLAIM_PROBLEMS["azp"])
    return claims


def complete_login(query: dict) -> str:
    """Handle the provider's redirect back; return a new session id."""
    if "error" in query:
        raise PermissionError(f"Sign-in was refused: {query.get('error_description') or query['error']}")
    c = config()
    with _lock:
        pending = _pending.pop(query.get("state", ""), None)
    if not pending or time.time() - pending["created"] > PENDING_SECONDS:
        raise PermissionError("The sign-in attempt expired or did not start here. Please try again.")
    meta = _metadata(c["issuer"])
    _https(meta["token_endpoint"])
    try:
        with _client(c) as client:
            tokens = client.fetch_token(meta["token_endpoint"], grant_type="authorization_code",
                                        code=query.get("code", ""), code_verifier=pending["verifier"])
    except Exception as error:                     # Authlib's OAuthError, or the connection failing
        hint = ""
        if any(word in str(error) for word in ("invalid_client", "client_secret", "client_assertion")):
            hint = (" The provider expects this console to prove who it is: either set the client secret in the "
                    f"environment variable named in var/auth.json ({c['client_secret_env'] or 'client_secret_env'}), "
                    "or register the console as a public client (see the SSO guide).")
        raise PermissionError(f"The SSO provider did not accept the sign-in: {error}.{hint}") from error
    claims = _verify_id_token(str(tokens.get("id_token", "")), meta, c, pending["nonce"])
    roles = claims.get(c["admin_claim"], [])
    roles = roles if isinstance(roles, list) else [roles]
    user = User(subject=str(claims.get("sub", "")),
                name=str(claims.get("name") or claims.get("preferred_username") or claims.get("email") or "user"),
                email=str(claims.get("email") or claims.get("preferred_username") or ""),
                roles=[str(r) for r in roles],
                admin=any(str(r) in c["admin_values"] for r in roles),
                expires=time.time() + float(c["session_hours"]) * 3600,
                id_token=str(tokens.get("id_token", "")))
    session = secrets.token_urlsafe(32)
    with _lock:
        _sessions[session] = user
    return session


def session_user(session: str) -> User | None:
    with _lock:
        return _sessions.get(session)


def logout(cookie_header: str | None) -> str | None:
    """End the console session. Returns the provider's sign-out address, if it has one, so the
    browser's provider session ends too; None means only the console session was ended."""
    user = None
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            with _lock:
                user = _sessions.pop(value, None) or user
    if user is None or not enabled():
        return None
    c = config()
    try:
        endpoint = _metadata(c["issuer"]).get("end_session_endpoint")
        if not endpoint:
            return None
        _https(endpoint)
    except PermissionError:                        # provider unreachable: the console session is ended anyway
        return None
    params = {"client_id": c["client_id"]}
    if user.id_token:
        params["id_token_hint"] = user.id_token
    if c["post_logout_redirect_uri"]:
        params["post_logout_redirect_uri"] = c["post_logout_redirect_uri"]
    return endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(params)


def cookie(session: str | None) -> str:
    secure = "; Secure" if config()["redirect_uri"].startswith("https://") else ""
    if session is None:
        return f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
    return f"{COOKIE}={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age={int(float(config()['session_hours']) * 3600)}{secure}"
