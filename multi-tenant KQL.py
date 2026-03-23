# 23 March 2026 v1.0
import msal
import requests
import json
import os
import base64
from datetime import datetime

# Entra app details:
# Use the organisations authority once, to establish a shared SSO session,
# then exchange that session for tenant-specific tokens later in the script.
CLIENT_ID = "<CLIENT_ID>"
SCOPES = ["https://graph.microsoft.com/ThreatHunting.Read.All"]
SSO_AUTHORITY = "https://login.microsoftonline.com/organizations"

# Force a new interactive authentication on every script run if set to True
# If FORCE_FRESH_AUTH_EACH_RUN is False we write a file to disk after SSO to store tokens. 
# If FORCE_FRESH_AUTH_EACH_RUN us True no tokens are stored on disk.

FORCE_FRESH_AUTH_EACH_RUN = True


# KQL query executed for each tenant. Edit here to change the query globally.
HUNTING_QUERY = "EntraIdSignInEvents | take 100"

# List of tenants to collect data from
TENANTS = [
    "<TENANT_ID#1>",
    "<TENANT_ID#2>",
    # Add more tenant IDs here as needed
]

# Create output locations once per run so every tenant writes to the same
# timestamped batch of files.
script_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(script_dir, "tenant_query_results")
os.makedirs(output_dir, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
run_summary_file = os.path.join(output_dir, f"{timestamp}_run_summary.txt")
cache_file = os.path.join(script_dir, "msal_token_cache.json")


def log_line(message):
    # Mirror status messages to both the console and the run summary file.
    print(message)
    with open(run_summary_file, "a", encoding="utf-8") as f:
        f.write(f"{message}\n")


def get_token_tid(access_token):
    # Decode the JWT payload locally so we can confirm the token really belongs
    # to the tenant we are about to query.

    # Decoding a JWT payload without verifying the signature is intentional here.
    # This code doesn't need to validate the token — it just reads the tid claim from a token that MSAL already acquired and validated during acquire_token_silent.
    # The goal is to guard against accidentally sending the wrong token to the wrong tenant, not to authenticate anything

    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        claims = json.loads(payload_json.decode("utf-8"))
        return claims.get("tid", "unknown")
    except Exception:
        return "unknown"


def get_account_for_tenant(msal_app, username, tenant_id):
    # Prefer the signed-in username when searching the cache, then fall back to
    # any cached account if the username-specific lookup returns nothing.
    accounts = msal_app.get_accounts(username=username)
    if not accounts:
        accounts = msal_app.get_accounts()
    for account in accounts:
        # In MSAL's cache, realm maps to the tenant ID.
        if account.get("realm") == tenant_id:
            return account
    return accounts[0] if accounts else None


def load_token_cache(path):
    # STORAGE: SerializableTokenCache is always an in-memory Python object.
    # It holds access tokens, refresh tokens, and ID tokens for the lifetime
    # of this process only — nothing is on disk yet at this point.
    cache = msal.SerializableTokenCache()

    # DISK → MEMORY: If a cache file exists from a previous run, deserialize it
    # into the in-memory object so prior refresh tokens can be reused without
    # prompting the browser again.
    # When FORCE_FRESH_AUTH_EACH_RUN is True the file is deleted before this
    # function is called, so the cache always starts empty in that mode.
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cache.deserialize(f.read())
    return cache


def save_token_cache(cache, path):
    # FORCE FRESH MODE: tokens stay in memory only and are discarded when the
    # process exits. Nothing is ever written to disk in this mode.
    if FORCE_FRESH_AUTH_EACH_RUN:
        return

    # MEMORY → DISK: Only write if MSAL flagged that the in-memory cache changed
    # (e.g. a new token was acquired or an existing one was refreshed).
    # Serializes the in-memory cache to JSON on disk so the next run can skip
    # the interactive browser prompt by loading those saved refresh tokens.
    if cache.has_state_changed:
        with open(path, "w", encoding="utf-8") as f:
            f.write(cache.serialize())


def acquire_tenant_token_silent(msal_app, scopes, account):
    # Try cache first, then force one refresh if no usable access token is found.
    if not account:
        return None

    result = msal_app.acquire_token_silent(scopes, account=account)
    if result and "access_token" in result:
        return result

    return msal_app.acquire_token_silent(
        scopes,
        account=account,
        force_refresh=True,
    )


def write_auth_error_file(output_folder, run_timestamp, tenant_id, details):
    # Keep tenant auth failure diagnostics in a consistent file format.
    output_file = os.path.join(
        output_folder, f"{run_timestamp}_{tenant_id}_auth_error.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Tenant: {tenant_id}\n")
        for detail in details:
            f.write(f"{detail}\n")
    return output_file


def write_tenant_results_file(output_folder, run_timestamp, tenant_id, results):
    output_file = os.path.join(
        output_folder, f"{run_timestamp}_{tenant_id}_results.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return output_file


def write_graph_error_file(output_folder, run_timestamp, tenant_id, status_code, response_text):
    output_file = os.path.join(
        output_folder, f"{run_timestamp}_{tenant_id}_error.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Error Code: {status_code}\n")
        f.write(f"Response:\n{response_text}")
    return output_file


def create_public_client(authority, token_cache):
    # Build one MSAL PublicClientApplication for a given authority.
    # A PublicClientApplication is for apps that cannot keep a secret (e.g. desktop
    # scripts, CLI tools) as opposed to ConfidentialClientApplication for web servers.
    #
    # authority — the login.microsoftonline.com URL that controls which tenant issues
    #   the token. SSO_AUTHORITY uses /organizations (any AAD tenant); tenant-specific
    #   authorities use /<tenant-id>.
    #
    # token_cache — the shared in-memory cache passed in from the caller. Sharing the
    #   same cache object across all clients means that a refresh token acquired during
    #   the initial SSO login is visible to every per-tenant client created later.
    return msal.PublicClientApplication(
        CLIENT_ID,
        authority=authority,
        token_cache=token_cache,
    )


# ── Token cache setup ──────────────────────────────────────────────────────
# Create one shared token cache so all authorities can reuse the same SSO session.
# All MSAL clients created below will be given the same cache object, which means
# a refresh token acquired during the initial interactive login is automatically
# available to every per-tenant client without any extra plumbing.
cache_reset_note = None
if FORCE_FRESH_AUTH_EACH_RUN:
    # Purge any saved cache before loading so this run always starts clean.
    # load_token_cache() will then return an empty SerializableTokenCache because
    # the file it would normally deserialize from no longer exists.
    if os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            cache_reset_note = "Deleted existing token cache file to force fresh authentication."
        except OSError as ex:
            # Deletion failed (e.g. file locked by another process) but the flag is
            # still True, so save_token_cache() will refuse to write, and interactive
            # login below will still run.
            cache_reset_note = (
                f"Unable to delete token cache file: {type(ex).__name__}: {ex}. "
                "Interactive sign-in is still forced for this run."
            )
    else:
        # Nothing to delete; fresh-auth mode is still honoured.
        cache_reset_note = "No token cache file found. Fresh authentication mode is active."

# Load (or create) the in-memory cache. If FORCE_FRESH_AUTH_EACH_RUN deleted the
# file above, this returns an empty cache. If a prior run saved tokens to disk and
# FORCE_FRESH_AUTH_EACH_RUN is False, the cache is pre-populated from that file.
token_cache = load_token_cache(cache_file)

# ── Initial SSO login ──────────────────────────────────────────────────────
# Do one interactive login at organizations authority to establish SSO.
# The /organizations authority accepts credentials from any Entra tenant,
# which seeds the shared cache with an ID token and refresh tokens that MSAL
# can later exchange for tenant-specific access tokens without opening a
# second browser window.
sso_app = create_public_client(SSO_AUTHORITY, token_cache)
# When forcing fresh auth, always skip the cache and go straight to browser sign-in.
# Otherwise, check if an account is already in the cache from a previous run.
accounts = [] if FORCE_FRESH_AUTH_EACH_RUN else sso_app.get_accounts()

# Open the run summary file in write mode ("w") to create it fresh for this run.
# All subsequent log_line() calls append to the same file in "a" mode, so this
# header block is always the first thing written.
with open(run_summary_file, "w", encoding="utf-8") as f:
    f.write(f"Run timestamp: {timestamp}\n")
    f.write(f"Output directory: {output_dir}\n")
    f.write(f"Token cache file: {cache_file}\n")
    f.write(f"Force fresh auth each run: {FORCE_FRESH_AUTH_EACH_RUN}\n")
    if cache_reset_note:
        f.write(f"Cache reset status: {cache_reset_note}\n")
    f.write(f"Tenant count: {len(TENANTS)}\n")
    f.write(f"Tenants: {', '.join(TENANTS)}\n\n")

log_line(f"Output directory: {output_dir}")
if cache_reset_note:
    log_line(cache_reset_note)

if accounts:
    # A cached account exists from a previous run and FORCE_FRESH_AUTH_EACH_RUN
    # is False. The in-memory cache was already populated by load_token_cache(),
    # so MSAL can acquire tokens silently in the tenant loop below without
    # showing a browser window at all.
    sso_account = accounts[0]
    log_line(
        f"Using cached SSO account: {sso_account.get('username', 'unknown')}")
else:
    # No usable cached account — open a browser sign-in window.
    # acquire_token_interactive() starts a local HTTP listener on port 8400,
    # launches the system browser to the Microsoft login page, and waits for
    # the OAuth redirect to bring the auth code back to that local port.
    log_line("No cached account found, performing one interactive sign-in...")
    try:
        # Launch a browser-based sign-in and listen locally for the redirect.
        login_result = sso_app.acquire_token_interactive(
            SCOPES,
            prompt="select_account",  # Always show the account picker.
            # Local redirect_uri port (must match app registration).
            port=8400,
        )
    except Exception as ex:
        # Wrap unexpected exceptions (e.g. port already in use, browser won't
        # open) in a dict so the failure path below handles them uniformly.
        log_line(f"Error during authentication: {type(ex).__name__}: {ex}")
        login_result = {
            "error": "exception",
            "error_description": str(ex),
        }

    if not login_result or "access_token" not in login_result:
        # The interactive login returned no token — could be user cancellation,
        # MFA failure, network issue, or a misconfigured app registration.
        # Write the details to a dedicated error file and exit; there is no
        # point continuing to the tenant loop with no SSO session.
        error_info = login_result or {}
        sso_error_file = os.path.join(output_dir, f"{timestamp}_sso_error.txt")
        with open(sso_error_file, "w", encoding="utf-8") as f:
            f.write("SSO sign-in failed.\n")
            f.write(f"Error: {error_info.get('error')}\n")
            f.write(f"Description: {error_info.get('error_description')}\n")
            f.write(
                "Tip: For true Windows SSO in Python, ensure msal[broker] is installed and your app registration includes broker redirect URI:\n")
            f.write(f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{CLIENT_ID}\n")
        log_line(f"SSO sign-in failed: {error_info.get('error_description')}")
        log_line(f"SSO error file: {sso_error_file}")
        raise SystemExit(1)

    # Login succeeded. Extract the signed-in user's profile from id_token_claims.
    # id_token_claims is a dict of standard OIDC claims (oid, preferred_username,
    # tid, etc.) decoded from the ID token that came back with the access token.
    # We copy preferred_username into a "username" key so get_account_for_tenant()
    # can search the MSAL cache by a consistent field name later in the loop.
    sso_account = login_result.get("id_token_claims", {})
    sso_account["username"] = login_result.get(
        "id_token_claims", {}).get("preferred_username", "unknown")
    # Persist the cache to disk now (if FORCE_FRESH_AUTH_EACH_RUN is False) so
    # the next run can skip the browser window by reloading these tokens.
    save_token_cache(token_cache, cache_file)

# sso_username is passed into every per-tenant lookup so MSAL can find the
# account in the shared cache that matches both the user and the target tenant.
sso_username = sso_account.get("username")
log_line(f"Authenticated user: {sso_username}")

# ── Per-tenant query loop ───────────────────────────────────────────────────
# Acquire tenant tokens silently using the same signed-in account.
# Each loop iteration targets one specific tenant and writes its own output file.
# No additional browser windows should appear here — all tokens are obtained by
# MSAL exchanging the refresh token (from the SSO login above) for a new
# access token scoped to the specific tenant authority.
for TENANT_ID in TENANTS:
    log_line(f"\n--- Processing Tenant: {TENANT_ID} ---")

    # Build a tenant-specific authority URL. Using the tenant ID (rather than a
    # domain name) is the most reliable identifier and avoids DNS-dependent lookups.
    tenant_authority = f"https://login.microsoftonline.com/{TENANT_ID}"

    # Create a per-tenant MSAL client. It shares token_cache with the SSO client,
    # so it can see the refresh token that was written during the SSO login.
    tenant_app = create_public_client(tenant_authority, token_cache)

    # Find the cached account entry that matches both the signed-in user and this
    # specific tenant. MSAL stores one account entry per (user, tenant) pair.
    tenant_account = get_account_for_tenant(
        tenant_app, sso_username, TENANT_ID)

    # [1/3 TOKEN ACQUIRED] MSAL returns a dict; result["access_token"] is the raw JWT string.
    # The token lives only in memory for the duration of this loop iteration.
    result = acquire_tenant_token_silent(tenant_app, SCOPES, tenant_account)

    if not result or "access_token" not in result:
        # Silent acquisition failed — most common causes:
        #   - The user has no guest account in this tenant.
        #   - The app hasn't been granted consent in this tenant.
        #   - The cached refresh token doesn't have a home-tenant entry for this tenant.
        # In SSO-only mode there is no fallback (no device code, no second browser
        # prompt), so log the failure and move on to the next tenant.
        error_info = result or {}
        log_line(
            f"Silent token acquisition failed for {TENANT_ID}: {error_info.get('error_description')}")
        output_file = write_auth_error_file(
            output_dir,
            timestamp,
            TENANT_ID,
            [
                "Unable to get tenant token silently (SSO-only mode, no device flow).",
                f"Error: {error_info.get('error')}",
                f"Description: {error_info.get('error_description')}",
                "Tip: User likely lacks guest account/consent in this tenant, or token cache lacks this tenant context.",
            ],
        )
        log_line(f"Auth error saved to: {output_file}")
        continue

    # Token acquired successfully. Persist the (potentially refreshed) cache to
    # disk so future runs can reuse these tokens without browser interaction.
    save_token_cache(token_cache, cache_file)

    # [2/3 TOKEN VERIFIED] Decode the JWT payload locally to confirm the tid claim
    # matches the tenant we requested. This is a sanity check, not a trust boundary —
    # Microsoft Graph enforces the real authorization server-side.
    token_tid = get_token_tid(result["access_token"])
    if token_tid != TENANT_ID:
        log_line(
            f"Tenant mismatch for {TENANT_ID}: token tid={token_tid}. Skipping to avoid wrong-tenant query.")
        output_file = write_auth_error_file(
            output_dir,
            timestamp,
            TENANT_ID,
            [
                f"Token tid mismatch: {token_tid}",
                "Token was not issued for requested tenant.",
            ],
        )
        log_line(f"Auth error saved to: {output_file}")
        continue

    log_line(f"Requested tenant: {TENANT_ID}")
    log_line(f"Token tenant (tid): {token_tid}")

    # [3/3 TOKEN USED] Attach the access token as a Bearer token in the Authorization
    # header. It is never written to disk, logged, or retained beyond this request.
    headers = {
        "Authorization": f"Bearer {result['access_token']}",
        "Content-Type": "application/json"
    }

    # Wrap the KQL string in the shape the Graph API expects.
    # The runHuntingQuery endpoint only accepts POST with a JSON body — there is
    # no GET equivalent.
    payload = {
        "Query": HUNTING_QUERY
    }

    # Submit the KQL to the Microsoft Graph security hunting endpoint.
    # timeout=60 prevents the script from hanging indefinitely if the Graph API
    # is slow or the network drops; adjust upward for very large result sets.
    response = requests.post(
        "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        headers=headers,
        # Automatically serializes payload to JSON and sets Content-Type.
        json=payload,
        timeout=60
    )

    if response.status_code == 200:
        log_line(f"Results for {TENANT_ID}:")
        # Parse the response body from JSON. The Graph API returns a "results"
        # array of row objects matching the KQL schema.
        results = response.json()

        # Write successful query output to a tenant-specific JSON file.
        output_file = write_tenant_results_file(
            output_dir,
            timestamp,
            TENANT_ID,
            results,
        )
        log_line(f"Results saved to: {output_file}")
    else:
        # Non-200 status — common causes: 401 (token expired or wrong scope),
        # 403 (missing consent / RBAC), 400 (malformed KQL), 429 (throttled).
        # Log both the status code and the raw response body, then save to file
        # so errors from different tenants are easy to compare after the run.
        log_line(f"Error for {TENANT_ID}: {response.status_code}")
        log_line(response.text)

        # Preserve the raw API error so failed tenants can be reviewed later.
        output_file = write_graph_error_file(
            output_dir,
            timestamp,
            TENANT_ID,
            response.status_code,
            response.text,
        )
        log_line(f"Error saved to: {output_file}")

log_line("Run complete.")
