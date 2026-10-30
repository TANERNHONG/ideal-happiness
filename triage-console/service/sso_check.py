"""Check the SSO settings in var/auth.json before anyone tries to sign in.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m service.sso_check

Reads the file, contacts only the configured provider (its discovery document
and its signing keys) and says what to fix. It signs nobody in and changes
nothing. Exit code 1 when something must be fixed.
"""
from __future__ import annotations

import os
import sys
import urllib.parse

from . import auth
from .config import PORT

OK, WARN, FAIL = "ok", "warn", "FAIL"
SHARED_ISSUERS = ("/common/", "/organizations/", "/consumers/")       # Entra's multi-tenant addresses


def checks() -> list[tuple[str, str, str]]:
    """(status, item, detail) for each check, in the order an administrator would fix them."""
    out: list[tuple[str, str, str]] = []
    add = lambda status, item, detail: out.append((status, item, detail))
    if not auth.AUTH_FILE.exists():
        add(FAIL, "settings file", f"{auth.AUTH_FILE} not found. Copy auth.example.json there and fill it in.")
        return out
    c = auth.config()
    add(OK if c["mode"] == "oidc" else WARN, "mode",
        "oidc: SSO is on" if c["mode"] == "oidc" else f"{c['mode']!r}: SSO stays off until mode is \"oidc\"")

    issuer = str(c["issuer"])
    parsed = urllib.parse.urlparse(issuer)
    if not issuer or "<" in issuer:
        add(FAIL, "issuer", "not filled in (still the example's placeholder?)")
    elif parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
        add(FAIL, "issuer", f"{issuer} must start with https://")
    elif any(part in issuer.rstrip("/") + "/" for part in SHARED_ISSUERS):
        add(FAIL, "issuer", f"{issuer} is a shared multi-tenant address. Use your tenant's own issuer, "
                            "e.g. https://login.microsoftonline.com/<tenant-id>/v2.0")
    else:
        add(OK, "issuer", issuer)

    client_id = str(c["client_id"])
    add(FAIL if not client_id or "<" in client_id else OK, "client ID",
        "not filled in (still the example's placeholder?)" if not client_id or "<" in client_id else client_id)

    redirect = urllib.parse.urlparse(str(c["redirect_uri"]))
    good_redirect = (redirect.hostname in ("localhost", "127.0.0.1") and redirect.port == PORT
                     and redirect.path == "/auth/callback")
    add(OK if good_redirect else FAIL, "redirect URI",
        f"{c['redirect_uri']} (register exactly this with the provider)" if good_redirect else
        f"{c['redirect_uri']}: the console receives the answer at http://localhost:{PORT}/auth/callback")

    secret_name = str(c["client_secret_env"] or "")
    if not secret_name:
        add(OK, "client type", "public client: no secret (register the console without one)")
    elif os.environ.get(secret_name):
        add(OK, "client type", f"confidential client: secret found in {secret_name}")
    else:
        add(WARN, "client type", f"{secret_name} is not set in this environment. Fine for a public-client "
                                 "registration; a confidential (web) registration will refuse the sign-in.")

    values = c["admin_values"] if isinstance(c["admin_values"], list) else []
    add(OK if c["admin_claim"] and values else WARN, "admin role",
        f"claim {c['admin_claim']!r} with {', '.join(map(str, values))}" if c["admin_claim"] and values else
        "admin_claim or admin_values is empty: people can sign in, but nobody will be an admin")
    add(OK if str(c["prompt"]) in auth.PROMPTS else FAIL, "account prompt",
        repr(c["prompt"]) if str(c["prompt"]) in auth.PROMPTS else f"{c['prompt']!r} must be one of {auth.PROMPTS}")
    try:
        hours = float(c["session_hours"])
        add(OK if 0 < hours <= 24 else WARN, "session length",
            f"{hours:g} hours" + ("" if 0 < hours <= 24 else ": expected between 0 and 24"))
    except (TypeError, ValueError):
        add(FAIL, "session length", f"{c['session_hours']!r} is not a number of hours")

    if any(status == FAIL for status, item, _ in out if item == "issuer"):
        return out
    # the provider itself: nothing below signs anyone in
    auth._discovery.pop(issuer, None)
    try:
        meta = auth._metadata(issuer)
        add(OK, "provider", "discovery document reached; it names the same issuer")
    except PermissionError as error:
        add(FAIL, "provider", str(error))
        return out
    try:
        keys = auth._key_set(meta, refresh=True)
        add(OK if keys.keys else FAIL, "signing keys", f"{len(keys.keys)} published at {meta['jwks_uri']}")
    except PermissionError as error:
        add(FAIL, "signing keys", str(error))
    offered = meta.get("id_token_signing_alg_values_supported") or ["RS256"]
    usable = [a for a in offered if a in auth.SIGNING_ALGORITHMS]
    add(OK if usable else FAIL, "signing algorithm",
        ", ".join(usable) if usable else f"the provider offers only {', '.join(offered)}; the console accepts asymmetric algorithms only")
    add(OK if meta.get("end_session_endpoint") else WARN, "sign-out at provider",
        "offered: signing out of the console also signs out of the provider" if meta.get("end_session_endpoint") else
        "not offered: signing out ends only the console session, so sign out of the provider in the browser too")
    if c["post_logout_redirect_uri"]:
        add(OK, "after sign-out", f"back to {c['post_logout_redirect_uri']} (register it with the provider too)")
    return out


def main() -> int:
    results = checks()
    width = max(len(item) for _, item, _ in results)
    for status, item, detail in results:
        print(f"[{status:>4}] {item:<{width}}  {detail}")
    failed = any(status == FAIL for status, _, _ in results)
    print("\nFix the FAIL lines, then restart the console." if failed else
          "\nReady: restart the console; the Datasets page offers Sign in with SSO.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
