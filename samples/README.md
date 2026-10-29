# Week 08 demo commands

Use **Node.js 24 LTS** (Long-Term Support) and npm. Check `node --version`.
In the master checkout, run `cd instructor` in **each new terminal** first.
In the student download, start in its top directory containing `weeks` and
`samples`. That is the **course-content root** used below and by slide captions
that say "repository root". Do not run the Windows and macOS alternatives both.

## 1. Complete browser sign-in (Blocks A, B and C)

PowerShell, from the course-content root:

```powershell
npm --prefix samples\mcp-starter ci
npm --prefix samples\oidc-web-app ci
npm --prefix samples\oidc-web-app run demo
```

macOS/Linux, from the same course-content root:

```bash
npm --prefix samples/mcp-starter ci
npm --prefix samples/oidc-web-app ci
npm --prefix samples/oidc-web-app run demo
```

Install before class. The last command builds the shared backend and starts
**all three servers**: the browser application's Backend-for-Frontend (BFF),
a maintained local identity provider, and the authenticated resource server.
The BFF is the OAuth client; the browser is its interface (user agent).
Open the printed **Course browser application** URL. Ports are allocated for
this run, not fixed at 5173 or 9100.

1. Click **Sign in with course identity**, then use the temporary viewer
   username/password printed by the launcher. Expect actual service data and
   incident `INC-2026-0016`, with no operator form.
2. Sign out and complete the provider's sign-out prompt. Sign in as the
   temporary operator, enter an update, choose **Review update**, and then
   **Confirm and publish**. The timeline must change, not just return HTTP 200.
3. Reload: the session persists. Sign out: protected requests are refused.
   Browser JavaScript receives no access/refresh tokens; the session identifier
   is an opaque, HttpOnly cookie.
4. Ctrl+C in the launcher closes only this demo's three listeners. Data,
   sessions, accounts and keys are in memory. Do not record the password banner.

This is genuine local password sign-in and an authorization-code exchange,
not the `/mint` shortcut below. It does not prove an external tenant was
configured. Its scopes (`status:read`, `incidents:read`, `incidents:write`)
are intentionally different from the teaching proxy's `campuspulse.*` scopes.
Do not mix the two configurations. See the
[browser application guide](../../../samples/oidc-web-app/README.md) and
[provider handoff](../provider-integration.md).

## 2. Small protocol experiments (Blocks A and B)

These scripts need **only the lab issuer**. No npm installation is needed for
these particular files. The browser demo and real Week 7 backend do need theirs.

Start a fresh **Terminal A**, from the course-content root:

```powershell
cd weeks\week08\samples
$env:PORT='9100'
node authz-server.mjs
```

macOS:

```bash
cd weeks/week08/samples
PORT=9100 node authz-server.mjs
```

Expect issuer `http://127.0.0.1:9100`, discovery and JWKS (JSON Web Key Set)
addresses, and an active key ID. Keep A running. Do not stop an unidentified
process if the port is occupied. Use fresh shells without overrides from other
labs (`AS_ISSUER`, `AS`, `JWKS_URI`, `MCP_RESOURCE`, `CLOCK_SKEW`).

In a fresh **Terminal D**, enter the sample directory:

```powershell
cd weeks\week08\samples
node pkce.mjs
node pkce-negative.mjs
node validate-token.mjs --variant valid --decode-only
node validate-token.mjs --variant valid --scope campuspulse.read
node tamper.mjs
node validate-token.mjs --token-file out\forged.txt --scope campuspulse.incident.write
```

macOS uses `cd weeks/week08/samples` and `out/forged.txt`; the other commands
are identical. These are the **client applications** for the small experiments.
`pkce.mjs` only prints a request and verifier: do not follow its unserved callback
as a sign-in demo. `pkce-negative.mjs` automates an actual successful code
exchange plus four refusals. Use section 1 for a browser callback that completes.

| Example | Expected result |
| --- | --- |
| Request builder / four-line hashing snippet | Fresh verifier, S256 challenge and discovered authorization URL |
| PKCE negatives | One HTTP 200; four HTTP 400 responses (wrong verifier, burned code, replay, missing PKCE) |
| Decode-only | Displays fields and says it stopped before validation |
| Valid token | Eight PASS lines and `ACCEPT 200` |
| Tamper then validate | `REJECT 401`, signature failure, exit code 1 |

Exit code **1 is expected for a rejected token**; run negatives separately,
not behind `&&` or a stop-on-error loop.

PowerShell negative battery, from D's sample directory:

```powershell
foreach ($v in 'expired','wrong-issuer','wrong-audience','not-yet-valid','no-scope','id-token','stale-kid') {
  node validate-token.mjs --variant $v --scope campuspulse.read
}
```

macOS:

```bash
for v in expired wrong-issuer wrong-audience not-yet-valid no-scope id-token stale-kid; do
  node validate-token.mjs --variant "$v" --scope campuspulse.read
done
```

All reject with 401 except `no-scope`, which rejects with 403. The validator
prints instructional verdicts; it is not itself an HTTP resource server.

Key rotation, from D (both shells):

```console
node -e "fetch('http://127.0.0.1:9100/rotate').then(r=>r.json()).then(console.log)"
node validate-token.mjs --variant valid --scope campuspulse.read
```

Rotation adds a key and retains old public keys. New tokens still pass. Restarting
the issuer is different: it discards all keys, so old tokens must be replaced.

The `alg: none` and RSA/HMAC-confusion examples are executable local regressions:

```console
node --test identity.test.mjs
```

That suite owns its own ephemeral issuer/proxy and closes them. It also runs
the HAR (HTTP Archive) sanitizer and evidence scanner on synthetic inputs, refresh
rotation/reuse, introspection and both stream-expiry modes. It uses a **stub**
upstream for policy isolation; section 5 separately tests actual MCP tools.

## 3. Proxy plus real Week 7 server (Block C)

Keep issuer **A** running from section 2. Start two additional terminals at the
course-content root; commands in different windows are not one pasteable block.

**Terminal B: proxy**, PowerShell:

```powershell
cd weeks\week08\samples
$env:PORT='8930'
$env:MCP_UPSTREAM='http://127.0.0.1:8931/mcp'
$env:ENFORCE_STREAM_EXPIRY='1'
node mcp-auth-proxy.mjs
```

macOS:

```bash
cd weeks/week08/samples
PORT=8930 ENFORCE_STREAM_EXPIRY=1 MCP_UPSTREAM=http://127.0.0.1:8931/mcp node mcp-auth-proxy.mjs
```

**Terminal C: backend**, PowerShell:

```powershell
cd samples\mcp-starter
npm ci
npm run build
$env:MCP_HOST='127.0.0.1'; $env:PORT='8931'
$env:DATABASE_URL=$null
npm run start:http
```

macOS:

```bash
cd samples/mcp-starter
npm ci
npm run build
MCP_HOST=127.0.0.1 PORT=8931 env -u DATABASE_URL npm run start:http
```

Install/build before class. Expect `store=memory` (or `store : memory`) and
the anonymous-server warning. **Clearing DATABASE_URL is mandatory**: the
following write is synthetic and must not touch an existing database.

**Terminal D: client**, from the sample directory used in section 2:

```console
node mcp-client-walk.mjs
node mcp-client-walk.mjs --tool post_incident_update
node mcp-client-walk.mjs --tool post_incident_update --login-as operator
node mcp-client-walk.mjs --tool get_incident
```

Each starts with no token and gets 401. The viewer read ends with 200; the viewer
write with 403; the operator write with 200. The last command shows the fixed
public classroom update in `incident updates`. HTTP 200 with a tool error is
failure, and a result labelled **STUB** is not proof a backend tool ran.

Loopback excludes other computers, not programs on this computer: another local
process can bypass B and call anonymous C directly. This is a teaching boundary,
not a deployment design. Use the authenticated handler shown by the browser
demo for your application.

## 4. Stream expiry (Block C)

Keep A running. In **B**, stop only your proxy with Ctrl+C, then run:

```powershell
$env:ENFORCE_STREAM_EXPIRY='0'; node mcp-auth-proxy.mjs
```

In **D**, run `node expiry-mid-connection.mjs --ttl 6 --watch 14`.
Expect negative `token_expires_in` values while the stream remains open.

Stop B with Ctrl+C and run:

```powershell
$env:ENFORCE_STREAM_EXPIRY='1'; node mcp-auth-proxy.mjs
```

In **D**, run `node expiry-mid-connection.mjs --ttl 8 --watch 22`.
Expect `token_expired` and `stream CLOSED` instead. On macOS prefix each B start
with `PORT=8930 ENFORCE_STREAM_EXPIRY=0` or `=1` and
`MCP_UPSTREAM=http://127.0.0.1:8931/mcp`, as on the slide.

This is a **synthetic Server-Sent Events (SSE)** stream measuring authorization
lifetime, not a full MCP subscription implementation. Only issuer and proxy
are needed for it; no backend tool executes.

## 5. Repeatable checks, public metadata and cleanup

From the course-content root, after the two locked installs in section 1:

```powershell
npm --prefix samples\mcp-starter run build
node --test weeks\week08\samples\identity.test.mjs weeks\week08\samples\demos.test.mjs
npm --prefix samples\oidc-web-app test
```

Use forward slashes on macOS. The real-backend suite verifies read/write
outcomes **and the timeline readback**; the browser suite checks real redirects,
password login, viewer denial, exact-text confirmation, refresh, logout and
negative cases. Browser tests use installed Edge/Chromium; if needed set
`BROWSER_EXECUTABLE` to an approved browser executable, not an unrelated process.

The public discovery/key examples require Internet, but no client registration:

```powershell
curl.exe -fsS --max-time 20 https://accounts.google.com/.well-known/openid-configuration
curl.exe -fsS -D - --max-time 20 https://www.googleapis.com/oauth2/v3/certs
```

On macOS replace `curl.exe` with `curl`. Key IDs, counts and cache ages change;
the slides' dated snapshots are not today's expected literal response.
Offline, read `fixtures/discovery-google.json`, `fixtures/jwks-google.json` and
the named `transcripts/` files with `Get-Content` (PowerShell) or `cat` (macOS).
Those files are fallbacks, not claims of a fresh execution.

Stop your A/B/C servers with Ctrl+C. In D, remove only the forged sample:
`Remove-Item -LiteralPath .\out\forged.txt` (PowerShell), or
`rm -f ./out/forged.txt` (macOS). Keep other evidence. Raw tokens, codes,
verifiers and cookies are credentials even on loopback; keep them ignored,
sanitize and scan before sharing. Conceptual comparisons of opaque OAuth tokens,
SAML and API keys are not additional implemented local-provider demos.
