# Multi-tenant KQL Queries using Delegated App

This project contains a Python script which runs a Microsoft Defender XDR Advanced Hunting KQL query across multiple Microsoft Entra tenants using one delegated user sign-in.

The script performs:

- One interactive sign-in against the `organizations` authority.
- Silent token acquisition per target tenant.
- Tenant ID (`tid`) verification before each query.
- Query execution via Microsoft Graph `security/runHuntingQuery`.
- Per-tenant output files plus a run summary.

## Files

- `multi-tenant KQL.py` - Main script.
- `FLOW_DIAGRAM.md` - Mermaid flow diagram showing the app's end-to-end execution flow (renderable in VS Code, GitHub, and diagrams.net).
- `FLOW_DIAGRAM.drawio` - Editable Draw.io version of the same flow diagram (open in [diagrams.net](https://app.diagrams.net) or the VS Code Draw.io extension).

## What It Does

1. Authenticates once with MSAL as a public client.
2. Reuses the shared token cache to request tenant-specific tokens silently.
3. Runs a global KQL query (`HUNTING_QUERY`) for each tenant listed in `TENANTS`.
4. Writes output into `tenant_query_results` with a timestamped naming pattern.

## Prerequisites

- Python 3.9+
- A Microsoft Entra app registration configured for delegated access
- API permission: `ThreatHunting.Read.All` (delegated)
- Admin/user consent in each tenant you query
- Redirect URI for interactive auth matching the script flow (localhost port 8400)

Install dependencies:

```bash
pip install msal requests
```

## Configure

Open `multi-tenant KQL.py` and set:

- `CLIENT_ID` to your app registration client ID.
- `TENANTS` to the tenant IDs to query.
- `HUNTING_QUERY` to your desired KQL query.
- `FORCE_FRESH_AUTH_EACH_RUN`:
  - `True`: always prompt interactive sign-in; no token cache written to disk.
  - `False`: reuse `msal_token_cache.json` for faster future runs.

### Required Before First Run

Update these values in `multi-tenant KQL.py` before running the script:

```python
CLIENT_ID = "<your-app-registration-client-id>"

TENANTS = [
    "<tenant-id-1>",
    "<tenant-id-2>",
    # Add more tenant IDs as needed
]
```

Where to get these values:
- `CLIENT_ID`: Microsoft Entra admin center -> App registrations -> your app -> Application (client) ID.
- `TENANTS`: Microsoft Entra admin center -> Overview -> Tenant ID (for each tenant you want to query).

Quick pre-run checklist:
- `CLIENT_ID` is from the same app registration that has `ThreatHunting.Read.All` delegated permission.
- Every tenant in `TENANTS` has consent for that app and permission.
- Tenant IDs are GUIDs (not tenant display names).

## Run

```bash
python "multi-tenant KQL.py"
```

## Output

The script creates:

- `tenant_query_results/<timestamp>_run_summary.txt` - overall run log.
- `tenant_query_results/<timestamp>_<tenantId>_results.json` - successful query output.
- `tenant_query_results/<timestamp>_<tenantId>_error.txt` - Graph API errors.
- `tenant_query_results/<timestamp>_<tenantId>_auth_error.txt` - token/auth issues.

## Notes

- The script is intentionally SSO-first: it does not fall back to device code flow in tenant failures.
- JWT decoding is used only to read the `tid` claim for safety checks, not as an authentication decision.
- Tokens are not written to logs or result files.

## Troubleshooting

- If interactive login fails, verify app registration redirect settings and local port availability (8400).
- If silent token acquisition fails for a tenant, confirm:
  - User has guest/member presence in that tenant.
  - App consent exists in that tenant.
  - Required Graph permission is granted.
- If Graph returns 403, check consent and role/permission scope alignment.
