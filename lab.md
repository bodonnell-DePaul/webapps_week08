# Week 8 — Guided Lab (35 min)

**Walk an OIDC redirect, prove your validator works, then put OAuth in front of last week's MCP server.**

**Scope:** a local protocol/claims demonstration, not real-provider login,
session logout or a production authorization boundary. Use
[provider integration](provider-integration.md) for the separate HW7 positive
path. Every student operates their own processes and accounts.

**Start commands:** [the demo runbook](samples/README.md) covers every server,
client, expected result and cleanup step. It also starts the complete browser
application, local provider and authenticated resource server with one command
after installation. Use that path to see a working sign-in and session, rather
than treating the parameter builder below as a complete web application.

> **What you leave with:** six terminal transcripts, all of which are required
> HW7 evidence. Redirect output to a file as you go and a third of the homework
> is done before you leave the room.

| Part | Min | |
| --- | ---: | --- |
| 0 — start three processes | 3 | |
| 1 — read a real provider, build the request | 5 | |
| 2 — break PKCE on purpose | 3 | |
| 3 — decode, validate, tamper | 8 | **do not skip** |
| 4 — key rotation | 2 | *skip this first if you are behind* |
| 5 — OAuth in front of your MCP server | 10 | **the point of the week** |
| 6 — the expiry collision | 3 | |
| wrap | 1 | |
| **Total** | **35** | |

The "before you start" checks below take about two minutes and are done while the
instructor sets up. They are not part of the 35.

---

## Before you start

| Requirement | Check | If it fails |
| --- | --- | --- |
| Node.js 24 LTS | `node --version` | Follow the getting-started recovery route |
| Your Week 7 MCP server | `curl http://127.0.0.1:8931/healthz` | See Part 5 — `MCP_UPSTREAM=stub` unblocks you |
| Internet, for one `curl` in Part 1.1 | — | Use `samples/fixtures/discovery-google.json` |
| A terminal | any | — |

```bash
cd weeks/week08/samples
mkdir -p out
```

PowerShell, starting in the course root containing `weeks` and `samples`:

```powershell
Set-Location weeks\week08\samples
New-Item -ItemType Directory -Force out | Out-Null
```

**The small scripts in this directory need no installed packages.** The real
Week 7 backend needs its locked `npm ci` and build before class; the complete
browser demo also needs its own locked install. See the demo runbook.

> **`out/` is scratch, and it must stay out of git.** Add `weeks/week08/samples/out/`
> to your `.gitignore` before you run anything. Nothing this lab produces is a
> production credential — but its tokens authorize local calls while it runs. The
> habit is the point, and in HW7 you will be doing this with your real tenant.

> **This lab uses the LOCAL lab authorization server, not the course tenant.**
> That is deliberate: it can mint an already-expired token, a wrong-audience
> token, and a wrong-issuer token on demand. Tokens work only in this local
> environment. **The real-tenant walk is HW7 Task 1–2** — you do it once, for
> credit, rather than twice.

> **Windows note.** Commands are given for bash. Where PowerShell differs
> materially, both forms are shown. `curl` in PowerShell 7+ is real curl; in
> Windows PowerShell 5.1 it is an alias for `Invoke-WebRequest` — run
> `Get-Command curl` to check, and use `curl.exe` if you are on 5.1.

---

## Part 0 — Start the three processes (3 min)

Three terminals.

**Terminal 1 — the lab authorization server (port 9100)**

```bash
node authz-server.mjs
```

Expected:

```text
  CSC 436 Week 8 — lab authorization server
  issuer     : http://127.0.0.1:9100
  discovery  : http://127.0.0.1:9100/.well-known/openid-configuration
  jwks       : http://127.0.0.1:9100/jwks.json
  active kid : ofjW-X2jv1eBzUWsrU0maDeyAftnqRxofLLpzqJitJc

  Keys die on exit. Tokens/codes work locally while running: redact them.
```

Your `kid` will differ — the RSA key is generated fresh at startup and thrown
away on exit. Redact tokens, codes and verifiers anyway: they work while this
environment runs, and the same capture habit applies to the real tenant.

**Terminal 2 — the authorization proxy (port 8930)**

```bash
node mcp-auth-proxy.mjs
```

It prints its policy table on startup. Read it — you will be asked to defend it.

**Terminal 3 — your Week 7 MCP server (port 8931)**

```bash
cd ../../../samples/mcp-starter
npm ci
npm run build
MCP_HOST=127.0.0.1 PORT=8931 env -u DATABASE_URL npm run start:http
```

PowerShell, from a new terminal at the course-content root:

```powershell
cd samples\mcp-starter
npm ci
npm run build
$env:MCP_HOST='127.0.0.1'; $env:PORT='8931'
$env:DATABASE_URL=$null
npm run start:http
```

Do the installs/build before class. Expect `store : memory`: clearing
`DATABASE_URL` prevents the synthetic operator write from reaching an existing
database. Stop each server only in its own terminal.

Leave terminals 1–3 running. Do the rest in a fourth.

---

## Part 1 — Read a real provider, then build the request (5 min)

### 1.1 Read a real provider's configuration

```bash
curl -s https://accounts.google.com/.well-known/openid-configuration
```

Find and write down four fields: `issuer`, `authorization_endpoint`,
`jwks_uri`, `code_challenge_methods_supported`.

> **Notice two things.** The token endpoint is on a *different host* from the
> issuer (`oauth2.googleapis.com`, not `accounts.google.com`) — which is why you
> never hardcode it. And `code_challenge_methods_supported` includes `plain`.
> A major provider still accepts the weak PKCE method for backwards
> compatibility. **You must not choose it.**

Then count the keys:

```bash
curl -s https://www.googleapis.com/oauth2/v3/certs
```

Count the keys actually returned; the count changes during rotation.
Selecting `keys[0]` works only by accident.
Offline? `fixtures/discovery-google.json` and `fixtures/jwks-google.json` are
snapshots taken 2026-08-15.

### 1.2 Build a PKCE pair and a complete authorization URL

```bash
node pkce.mjs 2>&1 | tee out/part1-pkce.txt
```

PowerShell:

```powershell
node pkce.mjs 2>&1 | Tee-Object -FilePath out\part1-pkce.txt
```

**Expected:** the discovered endpoints, a `code_verifier`, a `code_challenge`,
and an authorization URL carrying `code_challenge_method=S256`, `state`,
`nonce`, and `resource`.

**Inspect the URL as text.** This helper starts no callback listener and does
not establish a browser session. Do not interpret an unserved
`http://127.0.0.1:5173/callback` as a completed login. Part 2 performs a real
successful code exchange before testing replay; the
[complete browser demo](samples/README.md#1-complete-browser-sign-in-blocks-a-b-and-c)
performs the actual redirect, callback, validation and session creation.

> Append `&login_as=operator` to the authorization URL to sign in as the operator
> instead of the viewer. That one parameter is this lab's entire identity
> provider; use the real-provider handoff in HW7, not this mechanism in your app.

---

## Part 2 — Prove PKCE and single-use codes do something (3 min)

```bash
node pkce-negative.mjs 2>&1 | tee out/part2-pkce-negative.txt
```

**Expected — four results:**

```text
--- 1. exchange with the WRONG code_verifier -------------------
HTTP 400
{ "error": "invalid_grant",
  "error_description": "PKCE verification failed: S256(code_verifier) != code_challenge",
  "expected_challenge": "z_1m6MhVmoJag5sEMKeOZYshyxGMEGMJ5lHhsRzUDyg",
  "computed_challenge": "S8PQCZIMviVjOxZP2iqQH5p7gAQgZkWZjGWqrDhwH4E" }

--- 2. the RIGHT verifier, on that same code -------------------
HTTP 400  { "error": "invalid_grant",
            "error_description": "unknown or already-redeemed code" }

--- 3. a clean code, correct verifier, then replayed -----------
HTTP 200  {"token_type":"Bearer","expires_in":900,"scope":"openid campuspulse.read"}
HTTP 400  {"error":"invalid_grant","error_description":"unknown or already-redeemed code"}

--- 4. an authorization request with no PKCE at all ------------
HTTP 400
  invalid_request Missing: code_challenge , code_challenge_method …
```

**Result 2 is the one to think about.** *This* server consumed the code on the
failed attempt, so the honest client cannot recover either. RFC 7636 §4.6 only
requires that the wrong verifier be rejected; RFC 6749 §4.1.2 makes codes
single-use; [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html)
pushes toward treating a failed redemption as an attack signal. **Providers
differ — testing yours is an HW7 line item.** The reasoning for the strict
choice: a wrong verifier means somebody other than your client is holding the
code, and a retry for the honest client is also a retry for the attacker.

---

## Part 3 — Decode, then actually validate (8 min)

### 3.1 Decode. Notice that you have proved nothing.

```bash
node validate-token.mjs --variant valid --decode-only
```

You get a header and a payload. You have base64-decoded a string. **No claim on
that screen has been verified.**

### 3.2 Run the eight checks

```bash
node validate-token.mjs --variant valid --scope campuspulse.read \
  2>&1 | tee out/part3-valid.txt
```

**Expected:** eight `PASS` lines, then `ACCEPT 200`.

### 3.3 Tamper with the payload and watch it fail

Change one claim without touching the signature. This is the whole lesson.

```bash
node tamper.mjs
node validate-token.mjs --token-file out/forged.txt --scope campuspulse.incident.write \
  2>&1 | tee out/part3-tampered.txt
```

`tamper.mjs` mints a genuine viewer token, rewrites `roles` to `["operator"]` and
adds the write scope, re-encodes the payload, and **leaves the signature
untouched**. It prints exactly what it changed.

**Expected:**

```text
  PASS  alg is on the allow-list
  PASS  kid resolves in JWKS
  FAIL  signature verifies      cryptographic verification failed
REJECT 401  error_description="signature verification failed"
```

The decoder happily shows `"roles": ["operator"]`. The validator rejects it at
check 3. **Decoding is a display operation. Validation is a security operation.**

### 3.4 The negative battery

Run all five and keep every transcript:

```bash
for v in expired wrong-issuer wrong-audience no-scope id-token stale-kid; do
  echo "===== $v ====="
  node validate-token.mjs --variant "$v" --scope campuspulse.read
done 2>&1 | tee out/part3-negatives.txt
```

PowerShell:

```powershell
foreach ($v in 'expired','wrong-issuer','wrong-audience','no-scope','id-token','stale-kid') {
  "===== $v ====="
  node validate-token.mjs --variant $v --scope campuspulse.read
} 2>&1 | Tee-Object -FilePath out\part3-negatives.txt
```

**Fill in this table from your own output — it is an HW7 deliverable:**

| Variant | Which check failed first | Status | Why that status |
| --- | --- | --- | --- |
| `expired` | | | |
| `wrong-issuer` | | | |
| `wrong-audience` | | | |
| `no-scope` | | | |
| `id-token` | | | |
| `stale-kid` | | | |

> **The one to argue about:** `wrong-audience` is a genuine, correctly signed,
> unexpired token issued by your own tenant — and it gets **401**, not 403. Be
> able to say why.

---

## Part 4 — Rotation, and a key you have never seen (2 min)

> Skip this part first if you are short on time. It is the shortest and the
> least load-bearing.

```bash
curl -s http://127.0.0.1:9100/rotate
```

The response lists **both** kids: the new active one and the previous one, still
published. That is what a well-run rotation looks like — old keys stay in the
JWKS until every token signed with them has expired. Confirm a fresh token still
validates:

```bash
node validate-token.mjs --variant valid --scope campuspulse.read
```

Now force the other outcome — a token signed by a key that is **not** published:

```bash
node validate-token.mjs --variant stale-kid
```

**Expected:**

```text
  PASS  alg is on the allow-list
  FAIL  kid resolves in JWKS   kid=retired-2025-key not among [ … ]
  FAIL  signature verifies     cryptographic verification failed
REJECT 401  error_description="unknown signing key"
```

> **The 3am version of this:** your provider rotates and *removes* the old key
> while your service is holding a JWKS it cached with no TTL and no
> refresh-on-miss. Every valid token in production starts failing. Nothing was
> deployed. Same shape as the Week 1 certificate-expiry story.
>
> The proxy in Terminal 2 implements both rules — a 5-minute TTL and a refetch
> when a `kid` misses. Read `getKey()` in `mcp-auth-proxy.mjs`; it is fifteen
> lines and it is the difference between surviving a rotation and paging someone.

---

## Part 5 — Put OAuth in front of your MCP server (10 min)

### 5.1 The refusal that starts the protocol

```bash
curl -i -X POST http://127.0.0.1:8930/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: post_incident_update' \
  -H 'Mcp-Protocol-Version: 2026-07-28' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"post_incident_update"}}'
```

PowerShell:

```powershell
try {
  Invoke-WebRequest -Uri http://127.0.0.1:8930/mcp -Method POST -ContentType application/json `
    -Headers @{'Mcp-Method'='tools/call';'Mcp-Name'='post_incident_update';'Mcp-Protocol-Version'='2026-07-28'} `
    -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"post_incident_update"}}'
} catch { $_.Exception.Response.StatusCode; $_.Exception.Response.Headers['WWW-Authenticate'] }
```

**Expected:**

```text
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer resource_metadata="http://127.0.0.1:8930/.well-known/oauth-protected-resource", scope="campuspulse.incident.write"
```

Note the `scope` in the challenge: the server names what **this** operation
needs, not everything it supports, so the client can request least privilege.
Try the same call with `Mcp-Name: list_service_status` and watch the scope hint
change.

Then follow the pointer:

```bash
curl -s http://127.0.0.1:8930/.well-known/oauth-protected-resource
```

```json
{
  "resource": "http://127.0.0.1:8930/mcp",
  "authorization_servers": ["http://127.0.0.1:9100"],
  "scopes_supported": ["campuspulse.read", "campuspulse.incident.write"],
  "bearer_methods_supported": ["header"]
}
```

That is [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html), and MCP
specification 2026-07-28 makes publishing it a **MUST**.

> **What is *not* in that document:** the authorization server's `jwks_uri`. In
> RFC 9728 the `jwks_uri` field means "keys this **resource** signs its own
> responses with" — not the token-signing keys. A client finds those by following
> `authorization_servers` and reading that server's metadata. Publishing the AS's
> JWKS here is a common and confusing mistake.

### 5.2 The whole progression, automated

```bash
node mcp-client-walk.mjs 2>&1 | tee out/part5-viewer-read.txt
```

**Expected final lines:**

```text
[7] tools/call list_service_status WITH the access token
    HTTP 200
    body: {"result":{"content":[{"type":"text","text":"{\n  \"generatedAt\": …

======================================================================
RESULT  401 -> 200. The same call, the same server, one credential apart.
======================================================================
```

If the body says `"stub": true`, your Week 7 server is not reachable — see
troubleshooting. The authorization result is still valid evidence.

### 5.3 Per-tool scope: deny, then allow

```bash
node mcp-client-walk.mjs --tool post_incident_update \
  2>&1 | tee out/part5-viewer-write-denied.txt

node mcp-client-walk.mjs --tool post_incident_update --login-as operator \
  2>&1 | tee out/part5-operator-write-allowed.txt
```

**Expected — the viewer:**

```text
    scope=openid campuspulse.incident.write
           ^ from the WWW-Authenticate challenge — least privilege
    …
    scope         openid                  <- the tenant refused to grant the write scope
[7] HTTP 403
    WWW-Authenticate: Bearer error="insufficient_scope",
      scope="campuspulse.incident.write",
      resource_metadata="http://127.0.0.1:8930/.well-known/…"
RESULT  401 -> 403. Authentication succeeded; authorization did not.
```

**Expected — the operator:**

```text
    scope         openid campuspulse.incident.write
[7] HTTP 200
    body: {"result":{"content":[{"type":"text","text":"{\n \"posted\": true,
           \n \"ref\": \"INC-2026-0016\", \n \"feedEventId\": 1001\n}"}] …
RESULT  401 -> 200.
```

**Three** things happened, and you should be able to name all three:

1. The client asked for **only** the scope named in the 401 challenge — least
   privilege, driven by the server.
2. The **authorization server** refused to grant the viewer the write scope at
   all, because the *user* is not an operator. Requested and granted scope differ
   in the token response. That is the scope × role intersection, visible as data.
3. The **proxy** then refused the call, and named the missing scope in the
   challenge so a well-behaved client could step up.

> There is a second gate you did not trigger. `post_incident_update` requires
> the write scope **and** the `operator` role (see the policy table the proxy
> printed at startup). A token with the write scope but a `viewer` role gets
> **403 `insufficient_permission`** — and, unlike `insufficient_scope`, that one
> has no `scope` hint, because no amount of re-authorizing fixes it. Only an
> administrator can.

### 5.4 Read your audit log

Look at Terminal 2. One JSON line per decision:

```json
{"ts":"2026-08-15T20:47:20.047Z","decision":"deny","status":403,
 "reason":"insufficient_scope","required":"campuspulse.incident.write",
 "granted":["openid"],"method":"tools/call","name":"post_incident_update",
 "args":["body","confirm","isPublic","ref"],
 "sub":"a4f1c0de-…","jti":"03318502-…"}
```

**actor → tool → argument shape → decision → result**, with `jti` so a specific
credential is traceable. Note `args`: argument **names only, never values**. An
audit log full of argument values is a copy of your database with a search box on
it. Week 9 grades this log. Copy your own lines into `out/part5-audit.jsonl`.

### 5.5 Try to bypass the proxy

```bash
curl -s -X POST http://127.0.0.1:8931/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H 'Mcp-Method: tools/list' \
  -H 'Mcp-Protocol-Version: 2026-07-28' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"bypass","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
```

PowerShell:

```powershell
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"bypass","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
(Invoke-WebRequest -Uri http://127.0.0.1:8931/mcp -Method POST -ContentType application/json `
  -Headers @{'Mcp-Method'='tools/list';'Mcp-Protocol-Version'='2026-07-28'} -Body $body).Content.Substring(0,200)
```

It works, with **no token**. (If you get `-32602 … missing _meta`, you dropped
part of the envelope — spec revision 2026-07-28 requires it on every request.)

**The proxy is a perimeter control and the perimeter has a hole in it.** In the
lab, port 8931 binds to loopback so only you can reach it. In your deployment
that has to become a network policy, or the check has to move inside the server.
HW7 asks you to say which you chose and why.

---

## Part 6 — Where Week 7 and Week 8 collide (3 min)

An access token lives fifteen minutes. A `subscriptions/listen` stream lives for
hours, and takes **one** authorization decision — at open.

Reproduce the bug. In Terminal 2, stop the proxy and restart it unenforced:

```bash
# bash
ENFORCE_STREAM_EXPIRY=0 node mcp-auth-proxy.mjs
```

```powershell
# PowerShell
$env:ENFORCE_STREAM_EXPIRY='0'; node mcp-auth-proxy.mjs
```

Then:

```bash
node expiry-mid-connection.mjs --ttl 6 --watch 14 2>&1 | tee out/part6-bug.txt
```

**Expected:**

```text
t+  0s  open        {"exp":1786824030,"expires_in":6,"enforcing":false}
t+  6s  heartbeat   {"n":3,"token_expires_in":0,"still_streaming":true}
t+  8s  heartbeat   {"n":4,"token_expires_in":-2,"still_streaming":true}
t+ 12s  heartbeat   {"n":6,"token_expires_in":-7,"still_streaming":true}

t+ 14s  watch window over — the stream is STILL OPEN.
```

Now the fix. Restart the proxy normally (`node mcp-auth-proxy.mjs`) and re-run:

```bash
node expiry-mid-connection.mjs --ttl 8 --watch 22 2>&1 | tee out/part6-fixed.txt
```

**Expected:**

```text
t+  6s  heartbeat      {"n":3,"token_expires_in":2,"still_streaming":true}
t+  8s  token_expired  {"error":"invalid_token",
                        "error_description":"access token expired; re-authorize and reconnect"}

t+  8s  stream CLOSED by the authorization proxy at token expiry.
```

**Both transcripts are required HW7 evidence.** The homework asks you to document
the behaviour you *observed*, not the behaviour you intended.

---

## Wrap (1 min)

You should have, in `out/` (which is gitignored):

| File | Proves |
| --- | --- |
| `part1-pkce.txt` | a real discovery read and a PKCE-bearing authorization URL |
| `part2-pkce-negative.txt` | PKCE and single-use codes are actually enforced |
| `part3-valid.txt` | the eight checks passing |
| `part3-tampered.txt` | a modified claim rejected at the signature |
| `part3-negatives.txt` | six negative cases with their status codes |
| `part5-*.txt` | 401 → 403 → 200, and per-tool scope |
| `part5-audit.jsonl` | actor → tool → arguments → decision → result |
| `part6-bug.txt` + `part6-fixed.txt` | expiry on a long-lived connection |

Shut down: `Ctrl+C` in all three terminals. The authorization server's signing
key is destroyed with the process, so there is nothing to clean up and nothing to
rotate.

**These are six of HW7's fourteen artifacts.** The remaining eight need your own
provider and your own server — start Task 6 tonight, not on Sunday.

---

## Troubleshooting

### 1. Every token is rejected with `unknown signing key`

**Cause, almost always:** you restarted the authorization server. It mints a
**brand-new** RSA key at startup, so every token issued by the previous run is
now signed by a key that no longer exists.

**Fix:** get a fresh token — re-run whichever script produced the one you are
using. The proxy re-fetches the JWKS when it meets an unknown `kid`, so it heals
itself; the *token* is the stale thing, not the proxy.

If the authorization server is **down**, you will instead see
`unknown signing key` on every request because the JWKS fetch fails. Check:

```bash
curl -s http://127.0.0.1:9100/jwks.json
```

This is a real production failure mode reproduced accidentally. If it bit you,
note it in your HW7 AI-use log.

### 2. `upstream_unavailable` / `ECONNREFUSED 127.0.0.1:8931`

Your Week 7 MCP server is not running. Two options:

```bash
# preferred — fix the real thing
cd ../../../samples/mcp-starter && npm run start:http

# unblock now, fix later
MCP_UPSTREAM=stub node mcp-auth-proxy.mjs      # bash
$env:MCP_UPSTREAM='stub'; node mcp-auth-proxy.mjs   # PowerShell
```

`stub` mode answers the *shape* of an MCP response so every authorization result
in Part 5 is still real and still submittable. Say in your write-up that you used
it.

### 3. `EADDRINUSE` on 8930, 8931, or 9100

Something is already listening — often a previous run of this lab.

```bash
# macOS / Linux
lsof -ti tcp:8930 | xargs kill

# Windows PowerShell — find the PID, then stop that specific process
Get-NetTCPConnection -LocalPort 8930 -State Listen | Select-Object OwningProcess
Stop-Process -Id <PID> -Force
```

Or move the port: `PORT=8940 node mcp-auth-proxy.mjs` — but then the resource
identifier changes, so also set `MCP_RESOURCE=http://127.0.0.1:8940/mcp` on the
proxy **and** the authorization server, or every token fails audience validation.
That is itself a useful thing to see once.

---

## What this lab deliberately does not do

- **No TLS.** Everything is loopback HTTP so you can read it with `curl -i`.
  Real deployments require HTTPS everywhere; MCP specification 2026-07-28 assumes
  it.
- **No client authentication** at the lab token endpoint. A confidential client
  would authenticate; a public client uses PKCE alone.
- **No introspection path.** The proxy validates JWTs offline. The MCP
  authorization tutorial uses Keycloak introspection instead — both are correct,
  with the tradeoff from Block B.
- **The lab authorization server is not an identity provider.** "Login" is a
  query parameter. Use the **course tenant** for anything you would describe as
  authentication.

## Reference

- [MCP — Authorization, spec 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [RFC 9728 — Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
- [RFC 8707 — Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 6750 — Bearer Token Usage and the `WWW-Authenticate` challenge](https://www.rfc-editor.org/rfc/rfc6750.html)
