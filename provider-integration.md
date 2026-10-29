# From the local identity demonstration to your real application

The lab issuer is **not an identity provider you may deploy**. `login_as` selects
a role without authenticating anyone; `/mint` issues arbitrary fixtures;
`/logout` destroys no session. Its tokens are usable against the lab proxy
while it runs, so redact them too. Stop it when finished.

## 1. Obtain the course tenant handoff before starting HW7

The instructor provisions individual registrations and two synthetic accounts.
Copy these values into your **private environment**, not your repository:

| Value | Where to obtain/verify it |
| --- | --- |
| `ISSUER` | Exact issuer supplied for your registration; fetch its discovery URL |
| `DISCOVERY_URL` | Tenant handoff, ordinarily `ISSUER/.well-known/openid-configuration` |
| `WEB_CLIENT_ID` | Your web app registration (never a classmate's) |
| `MCP_CLIENT_ID` | Separate MCP client registration |
| `REDIRECT_URI` | An exact registered callback, including port and path |
| `MCP_RESOURCE` / `MCP_RESOURCE_URL` | Canonical MCP resource URL sent in the authorization flow; use the same configured registration |
| `OIDC_AUDIENCE` | Exact access-token audience for that resource registration, not the web client's ID-token audience |
| Authenticated starter scopes | `status:read`, `incidents:read`, `incidents:write` |
| Test identities | One viewer, one operator; synthetic accounts you operate yourself |

The issuer, client ID and resource/audience are **three different identifiers**.
A web ID token names the web client; an MCP access token names the MCP resource.
Do not substitute one for another just to make validation pass.
Some providers use a dedicated API audience identifier distinct from the public
resource URL; document that mapping and configure `OIDC_AUDIENCE` accordingly.
The local teaching issuer/proxy uses `campuspulse.read` and
`campuspulse.incident.write` instead. Those are a **different demonstration
profile**, not automatically accepted aliases in the authenticated starter.

If any handoff value or account is missing, stop real-provider integration and
report that specific blocker in D2L. Complete the local lab while the instructor
repairs provisioning. Local fixtures may earn the diagnostic homework rows;
they do not establish real-provider login or clear the Authorized gate.

The course now supplies a maintained-library
[browser OIDC/BFF integration](../../samples/oidc-web-app/README.md), including
callback/session handling, the authenticated MCP connection and an exact-text
operator approval step. Start with its full local standards-provider demo,
then configure the same application against your assigned tenant.

The earlier first-web-app sample still provides a UI/API contract, **not an
OIDC implementation**. Its `ALLOW_WRITES=1` flag remains loopback practice only.
Use the new BFF routes from your frontend rather than enabling that flag in
public. If the actual tenant or an approved alternative integration is missing,
record **real-provider** sign-in as blocked; the local demo is not evidence that
an external tenant was provisioned.

## 2. Check the registration, not a tutorial's defaults

In the tenant's client/application registration:

1. Enable authorization-code flow and S256 PKCE. Disable implicit/password grants.
2. Register the exact callback your app handles. Do not use wildcard callbacks.
3. For a browser/public client, do **not** provision or embed a client secret.
   For a confidential backend client, keep its secret only in backend configuration.
4. Define the read/write scopes for the resource server. Assign operator role only
   to the operator account; a client's granted scope is not a user's role.
5. Configure the audience mapping for the MCP resource. Verify a decoded token's
   actual `aud`; the `resource` parameter alone cannot configure a provider.
6. If the provisioned provider cannot issue the audience/scopes required by the
   pinned MCP authorization profile, request the course-compatible registration.
   Do not disable audience validation or claim a provider supports an untested flow.

Export redacted settings as evidence. These steps describe the settings to verify;
your handoff must include the tenant's concrete screen names or an importable
configuration. A generic provider-homepage link is not a sufficient handoff.

## 3. Walk the real code flow once

**Supported application route:** run
`npm --prefix samples\oidc-web-app run demo` after the locked installs in its
[README](../../samples/oidc-web-app/README.md). A real local `oidc-provider`
password page, authorization code, S256 verifier, signed ID/access tokens and
JWKS verification connect to the actual authenticated MCP handler. Temporary
viewer/operator accounts are printed for that run. The BFF stores tokens on
the server; the browser gets only an opaque `HttpOnly` cookie.

For your assigned tenant, copy the BFF's `.env.example` into private
configuration, use its exact `/auth/callback` URL and registered confidential
client method, then run `npm start` in that sample. Complete the same browser
steps and label those captures as external-tenant observations.

**Optional hand-run protocol diagnostic:** the helper below is for understanding
the wire parameters, not a substitute for the working application's callback
and sessions. It assumes its own **public-client** registration; never substitute
the BFF's confidential-client ID without its required backend authentication.

PowerShell, from the course root:

```powershell
New-Item -ItemType Directory -Force raw-evidence,evidence | Out-Null
# Add raw-evidence/ to your project's .gitignore before capture.
Invoke-WebRequest $env:DISCOVERY_URL -OutFile evidence\01-discovery.json
node weeks\week08\samples\pkce.mjs `
  --discovery $env:DISCOVERY_URL --client-id $env:MCP_CLIENT_ID `
  --redirect-uri $env:REDIRECT_URI --resource $env:MCP_RESOURCE `
  --scope "openid status:read incidents:read"
```

The helper prints a verifier and URL. Treat its output as raw credentials, not
submission evidence. Open the URL with DevTools **Preserve log** enabled. Sign
in as the viewer. Your callback should check returned `state` against the
one saved before redirect and `iss` when the provider returns it. Exchange the
code exactly once, with that verifier, client ID, callback, and resource.
The helper prints a Bash token-request template; in PowerShell use:

```powershell
# CODE and VERIFIER are the just-captured values in your private environment.
$discovery = Get-Content evidence\01-discovery.json -Raw | ConvertFrom-Json
$tokens = Invoke-RestMethod -Method Post -Uri $discovery.token_endpoint -Body @{
  grant_type='authorization_code'; code=$env:CODE
  client_id=$env:MCP_CLIENT_ID; redirect_uri=$env:REDIRECT_URI
  code_verifier=$env:VERIFIER; resource=$env:MCP_RESOURCE
}
# Do not print or commit $tokens. Decode only for your redacted claims matrix.
```

This is a **public-client hand-run diagnostic**. A confidential registration
also needs its registered token-endpoint authentication method. Do not guess
Basic vs body authentication. Export the HAR into `raw-evidence`, sanitize,
then scan using the actual values you handled:

```powershell
node weeks\week08\samples\sanitize-har.mjs raw-evidence\authorize.har evidence\03-authorize.har
node weeks\week08\samples\scan-evidence.mjs evidence --secrets-from raw-evidence\known-values.txt
```

Repeat with a **fresh** authorization code and intentionally wrong verifier.
Record whether that code can subsequently be redeemed correctly. Do not infer
your provider's behavior from the local issuer.
The PKCE helper prints parameters; it does not install a callback handler,
bind state to an application session, or establish a logged-in browser.

## 4. Integrate, rather than merely decode

### Use the supported authenticated MCP entry

The shared starter now implements JWT verification and per-request caller/audit
propagation. Use it rather than writing another authorization server or placing
the teaching proxy in front of an anonymous upstream:

```powershell
Set-Location samples\mcp-starter
# Copy examples\.env.authenticated.example to your ignored .env and configure it.
npm run build
npm run start:http:auth
```

Follow [Authenticated HTTP integration](../../samples/mcp-starter/AUTHENTICATED-HTTP.md)
for exact settings: `OIDC_ISSUER`, `OIDC_AUDIENCE`, trusted `OIDC_JWKS_URI`,
`MCP_RESOURCE_URL`, and claim/role mappings. `OIDC_SCOPE_CLAIM` selects the claim
field; it does not rename its scope values. The default profile accepts RS256
and the three starter scopes above.

If your provisioned tenant uses the teaching profile's names, the authenticated
entry now supports this **explicit configuration**, without a custom verifier:

```dotenv
OIDC_SCOPE_CLAIM=scp
OIDC_SCOPE_MAP='{"campuspulse.read":["status:read","incidents:read"],"campuspulse.incident.write":["incidents:write"]}'
```

Use `scope` instead of `scp` when that is the actual signed claim. With this
map selected, request the provider names (`openid campuspulse.read` for the
read-only hand-run flow), not the default internal names. The map replaces
default identity mapping; unlisted raw scopes grant nothing, and it never
grants the operator role. Metadata/challenges advertise provider names while
audit records effective internal permissions. Use the matching provisioned
profile, never disabled issuer/audience/signature checks.

For the supported path, connect the MCP client directly to this authenticated
entry through the controlled TLS ingress. The unchanged teaching proxy expects
different scope names and is not a drop-in intermediary for this profile.
Keeping it would require an explicitly tested policy adapter; it is not required.

Stop the anonymous process you own or choose a free loopback `PORT`. Confirm the
new process's `/healthz` reports `authorization: "bearer-jwt"`, then test a
well-formed unauthenticated MCP request returning 401. A failed authenticated
startup does not replace a different process still listening on the old port.
Follow the returned `resource_metadata` URL; the default is
`/.well-known/oauth-protected-resource/mcp`, not the teaching proxy's root path.

For deterministic local verification, run `npm test` in the starter or its
`scripts\authenticated-http.test.mjs` suite after building. These tests generate
real signed tokens and ephemeral JWKS servers; they are not external IdP login,
consent, refresh or deployment evidence. `OIDC_ALLOW_HTTP_LOOPBACK=true` permits
only the explicit loopback test profile, never external insecure trust.

### Integrate browser login and session handling separately

Use the supplied [browser application](../../samples/oidc-web-app/README.md),
which uses `openid-client`, or an approved maintained client for your stack.
The supported BFF implements the following responsibilities; preserve them when
adapting the frontend or changing providers:

- retain state/nonce/verifier only for the pending login and validate the callback;
- validate the ID token's signature, issuer, client audience, expiry and nonce;
- create a session or hold access tokens in memory, not ship secrets in React;
- validate the API access token's signature, issuer, **resource** audience and
  expiry on every request, then separately check role and scope;
- use the authenticated subject in the actual state-changing handler and audit;
- clear the local application session at logout and document any still-valid
  access token. Provider logout and refresh-token revocation are separate actions.

`start:http:auth` remains the resource server; the new browser BFF supplies the
client responsibilities. Its session ID rotates after login, absolute/idle
expiry is bounded, refresh is serialized, and failed renewal signs the user out.
Its operator review records are session-bound, expire and are consumed once
before the stored arguments are written. A caller cannot replace the text in
the confirmation request. This approval guarantee covers that browser path;
other MCP clients need their own trusted host/operator approval.

For the BFF route, tokens and client credentials stay server-side; the browser
receives only the protected session cookie. Store
deployment credentials through the provisioned secret mechanism, never React
environment variables, committed files or evidence captures. Operator writes
need a real authorization boundary—not enabling the first-web-app's local flag
on a public listener.

Do not trust a role supplied in a form or an `X-User` header from an external
client. A reverse-proxy topology also needs a non-bypassable authenticated or
private upstream hop. Merely putting two processes on the same laptop does not
prevent other local processes from reaching the unauthenticated upstream.

The supplied `mcp-auth-proxy.mjs` is for **loopback diagnostics**. A 200 with
`MCP_UPSTREAM=stub` proves a policy branch only, not MCP execution, persistence,
real login, end-user audit identity or a safe hosted deployment.

### The shared starter's caller boundary

The starter exposes `createServer(store, validatedCaller)` in
`samples/mcp-starter/src/server.ts`. Its default `developmentCaller()` is
deliberately unauthenticated. `start:http:auth` builds the caller **per request**
after validation and passes it explicitly. Preserve that behavior if adapting
the entry; never overwrite one global caller when requests may overlap.

Its `CallerContext` fields are:

| Field | Trusted source |
| --- | --- |
| `issuer` | Validated issuer used to scope the audited subject |
| `subject` | Validated, nonempty `sub` |
| `clientId` | Configured validated client-identity claim; authenticated mode rejects missing/empty identity |
| `scopes` | Granted starter permissions from the configured verified claim |
| `isOperator` | Trusted role mapping, not a request argument or caller-set header |

The authenticated starter expects `status:read`, `incidents:read` and
`incidents:write`. The local teaching proxy's `campuspulse.*` names are not
synonyms. Configure the registration to emit the supported values or set the
explicit `OIDC_SCOPE_MAP` profile above. Unknown scopes grant nothing.
The write handler still requires `isOperator`. If you added a third read tool,
add its explicit policy entry without weakening deny-by-default.

Verify that two different synthetic users produce their own subjects in the
**upstream tool audit**, not merely in the proxy log. Forwarding a bearer header
to an upstream that still calls `developmentCaller()` does not accomplish this.
The supported authenticated entry implements this boundary; the anonymous
`start:http` entry does not. Combine it with the browser BFF for login/session
handling and argument-bound approval, then separately rehearse the provisioned
provider's logout, revocation and token-expiry policy.

## 5. Minimum acceptance record

Reuse one evidence index for HW7, the Authorized gate and final. Identify each
row as **real provider**, **local fixture**, or **not yet verified**:

The earlier public deployment must already reject unauthenticated writes with
401/403 and leave state unchanged. Preserve that regression while adding
authenticated operator writes for **Gate 6**. Passing local fixture tests is not
permission to enable a local-write flag on a public listener.

1. Browser login with your real viewer and operator accounts.
2. Viewer read allowed; viewer write denied; operator write allowed.
3. A token with write scope but no operator role denied, and an operator token
   with only read scope denied (local fixtures are appropriate for these).
4. Missing, expired, wrong-issuer/audience and tampered credentials denied.
5. A real tool call through the protected path, and a direct-origin bypass test.
6. Application logout, refresh and expiry; local synthetic stream lifetime labeled
   separately from a real authenticated stream.

Use [the deployment runbook](../../docs/deployment-runbook.md) for the network,
TLS and secret-storage boundary. A successful local demonstration must never be
reported as a successful production/IdP integration.

## 6. Public session and authorization reference

These explanations remain available even when the lecture runs out of time.
Do not depend on private instructor notes for HW7.

**A scope and a role answer different questions.** A scope limits what the
client was granted permission to request. A role describes the user's assigned
authority. Effective permission is their intersection, followed by object-level
checks. A viewer with write scope still fails the operator-role check; an
operator using a read-only client still cannot write.

**RBAC** checks a role, such as operator. **ABAC** additionally checks trusted
attributes, such as whether the incident and operator belong to the same
synthetic campus. Never accept the actor's role/campus merely because a request
body asserted it. Map validated claims and server-owned records to the decision.

**SPA vs BFF:** a browser SPA cannot keep a shared client secret. A backend-for-
frontend keeps OAuth tokens server-side and gives the browser a session cookie.
This reduces token theft through JavaScript but does not eliminate XSS: malicious
script may still issue actions using the user's active browser session.

For a real HTTPS BFF, inspect its actual session cookie:

| Attribute | Meaning |
| --- | --- |
| `Secure` | Send only over HTTPS; the local HTTP fixture is not production proof |
| `HttpOnly` | Browser JavaScript cannot read the cookie; it can still send requests |
| `SameSite=Lax` or stricter justified choice | Restricts cross-site cookie delivery; use the framework's CSRF protection too |
| `Path` and omitted/bounded `Domain` | Limit where the cookie is sent; avoid unnecessary subdomain sharing |
| `Max-Age` / `Expires` | Browser storage lifetime, not automatic server-side session revocation |

Capture the header with values redacted, then verify login, one authorized
operation, a denied operation and logout. The logout handler should invalidate
the application session and expire the cookie using matching path/domain
attributes. A client-side redirect alone does neither.

**Refresh** exchanges a refresh credential for a new access token. Rotation
replaces the refresh credential; reuse detection can revoke its family.
**Logout** ends the application/provider session according to the implemented
flow. **Revocation** invalidates a credential according to the provider's model.
An already-issued self-contained access token may remain accepted until expiry
unless the resource server also checks revocation. State that residual lifetime.

Use the local issuer to rehearse deterministic negatives, not to prove real
session logout. Its `/logout` intentionally explains that it has no session.
A long-lived stream also needs lifetime supervision: authenticating its opening
request does not keep the decision valid forever. Reconnect with a fresh
credential after termination; do not put bearer tokens in stream URLs.

For the no-personal-AI route, use the [HW7 supplied draft](../../docs/non-ai-review-artifacts.md).
