# SSO and datasets

Looking, analysing, reviewing and querying work without signing in. **Adding a
dataset, importing its archives into the pipeline and training models** change
the data everyone relies on, so they need an administrator signed in with your
organisation's single sign-on (SSO).

## Turning on SSO (administrator, once)

SSO is off until a configuration file exists on this laptop. Nothing in the
browser can switch it on or decide who is an admin.

1. **Install** the console's sign-in packages, once, from `triage-console`:
   `..\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
2. **Register** the console with your identity provider. Ask IT which of the
   two kinds of registration they want; for Microsoft Entra ID:

   | Kind | In Entra ID | In `var/auth.json` |
   |---|---|---|
   | **Public client** (no secret; simplest for one laptop) | Platform *Mobile and desktop applications*, redirect URI `http://localhost:8765/auth/callback` | `client_secret_env` empty (`""`) |
   | **Confidential client** (with a secret) | Platform *Web*, the same redirect URI, and a client secret | `client_secret_env` names the environment variable that holds the secret |

   Either way, add an app role such as `OT-Console-Admin`, and assign it to the
   people allowed to add data and train models.
3. **Fill in the settings.** Copy `triage-console/auth.example.json` to
   `triage-console/var/auth.json` and fill in the issuer, the client ID and the
   role name. For Entra ID, use your tenant's own issuer
   (`https://login.microsoftonline.com/<tenant-id>/v2.0`), not `common` or
   `organizations`: the console checks that the provider's settings name
   exactly this issuer. Two optional settings:

   | Setting | What it does |
   |---|---|
   | `prompt` | `select_account` (the default): the provider shows its account picker, so nobody is signed in without choosing. `login`: asks for the password every time. `""`: leaves it to the provider. |
   | `post_logout_redirect_uri` | Where the provider sends the browser after signing out, e.g. `http://localhost:8765/`. Register it with the provider too. Empty: the provider shows its own signed-out page. |

4. **Secret** (confidential client only): put it in the environment variable
   named in `client_secret_env` (the example uses `SMRT_OT_CONSOLE_CLIENT_SECRET`),
   never in the file.
5. **Check** the settings: `..\.venv\Scripts\python.exe -m service.sso_check`.
   It contacts only the provider, signs nobody in, and says what to fix, line by
   line.
6. **Restart** the console. The Datasets page now offers **Sign in with SSO**.

How it works: OpenID Connect sign-in with PKCE, through the Authlib library.
The ID token the provider returns is checked before anyone is signed in:
- its signature, against the provider's published keys;
- that it was issued by your provider, for this console, for this sign-in
  attempt, and is still valid.

The console only talks to the provider during sign-in and sign-out. Sessions
last `session_hours` (8 by default) and end when the console restarts. When
someone is signed in, the activity log records their account instead of the
name typed in Settings.

**Signing out on a shared laptop.** *Sign out* ends the console session and,
when the provider offers it, the provider's session in the browser too, so the
next person has to choose or enter their own account. If the check says the
provider offers no sign-out, also sign out of the provider in the browser.

**If sign-in fails:**

| The console says | What to do |
|---|---|
| The provider's settings name a different issuer | Make `issuer` exactly what the provider reports, for Entra the form with the tenant ID. |
| The provider expects this console to prove who it is | The registration is confidential: set the secret's environment variable, or ask IT for a public-client registration. |
| The ID token's signature did not match | The issuer or tenant is probably wrong; run the check. |
| Signed in as …, but this needs the admin role | Ask IT to assign the app role, then sign out and in again. |

## Adding data and training

On the **Datasets** page (admin only):

| Step | What happens |
|---|---|
| **Add a dataset** | Registers a folder of monthly archives named like the existing ones (`2026-08 NSEWL SCS.zip`) for one log type. Nothing changes yet. |
| **Import** | Copies the archives into the pipeline's raw folder (`data/phase0_raw/archives`). An archive that is already there with the same size is skipped; one with different content is reported, never overwritten. |
| **Train** | Runs the pipeline for that log type from the chosen phase, with the model zoo, and shows its output. One run at a time; it can be stopped. Retraining replaces that log type's results, models and reports. |

A log type the pipeline cannot read yet can be registered, but not trained: a
developer first adds a Phase 1 classifier for it
(`pipeline/phase1_classify/<type>.py`).

Every addition, import and training run is in the activity log.
