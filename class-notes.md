# Week 8: Identity: OAuth, OIDC, Claims — and Authorizing the MCP Server — class notes

These notes contain the student-visible teaching material and examples. Complete the exercises individually. Instructor delivery notes and answer keys are not included.

## Weekly session — Identity: OAuth, OIDC, Claims — and Authorizing the MCP Server

Review, preparation, logistics, teaching, individual practice, and the end-of-class brief

## Short review

### The words behind "Sign in with..."

| Term | Think of your student project |
| --- | --- |
| Authentication | "Who signed in?" A campus identity check |
| Authorization | "May this person post a Wi-Fi outage update?" |
| OAuth | Delegated authorization: let an app act without giving it your password |
| OpenID Connect (OIDC) | The login layer on OAuth: tells the client who signed in |
| Access token | A temporary credential the app presents to a service |
| Scope | A named permission, such as read status but not write updates |

### Acronyms you will see on the wire

| Short name | Full name and job |
| --- | --- |
| API | Application Programming Interface: software calls |
| JSON | JavaScript Object Notation: structured data |
| JWT | JSON Web Token: a claims format |
| JWKS | JSON Web Key Set: public verification keys |
| PKCE | Proof Key for Code Exchange ("pixy") |
| HTTP / TLS | Hypertext Transfer Protocol / Transport Layer Security |

### What you shipped last week, exactly as you left it

- Recall the Week 7 starter's `/healthz` response:
  `"authorization":"none"`
- It has real tools, a real state-changing action, and a real MCP App
- Without authorization, anyone who can reach that port can call its tools;
  this is why the Week 7 exercise stayed on loopback

## Prelecture review

### Two answers from your prep, before we start

#### Q1 — What is OAuth actually for?

**B — letting one app act on your behalf at another, without your password.**
If you picked "proving who you are," that is the mistake this block spends its
first minutes correcting.

#### Q4 — What does jwt.io prove?

**D — decoding alone only shows contents, not whether they are trustworthy.**
A debugger may also verify a signature if correctly configured; that still does
not decide your application's permissions. Do not upload real tokens.

## Weekly logistics

### Addresses you will configure

- **URL (Uniform Resource Locator):** a web address you can open
- **URI (Uniform Resource Identifier):** an identifier; our callback URIs are URLs
- **Endpoint:** a specific address an application calls for one job
- **Callback:** where the provider sends your browser back after approval
- **HTTPS:** HTTP protected by TLS; encrypts traffic between endpoints

### Configuration is an address book, not magic

| Setting | What it identifies |
| --- | --- |
| Tenant / issuer | Provider workspace / exact token issuer |
| Discovery URL | Endpoint directory at a trusted web address |
| Client ID | Public registration identifier for your app, not a password |
| Redirect URI | Registered callback address receiving the code |
| Resource / audience (`aud`) | Service requested / token's intended recipient |
| Client secret | Backend-only credential; never put it in browser code |

### Two scopes, one isolation rule

#### Permissions to configure

- Read: `campuspulse.read`
- Write: `campuspulse.incident.write`
- Use your assigned registrations, not another student's

#### Keep it isolated

- Keep the server on `127.0.0.1` (loopback: only this computer)
- Do not expose an unauthenticated endpoint
- Missing tenant values: contact the instructor

## Block A — Delegation and the flow

### Before any command: choose the course root

| Your starting point | Where to run commands |
| --- | --- |
| Master checkout (`instructor` + `student`) | `cd instructor` in each new terminal |
| Downloaded student course | Stay in its top folder, containing `weeks` and `samples` |
| Caption says "repository root" below | It means this **course-content root**, not the master checkout |
| PowerShell / macOS slides | Choose one shell; do not run both alternatives |
| Runtime | Node.js 24 LTS (Long-Term Support); use `node --version` to check |

**Sources**

- Course — [Every demo: servers, clients, expected results, cleanup](samples/README.md)

### First, a login that comes back to your app

```powershell title="PowerShell - course-content root - one terminal"
npm --prefix samples\mcp-starter ci
npm --prefix samples\oidc-web-app ci
npm --prefix samples\oidc-web-app run demo
```

> **Key idea**
>
> The launcher starts the browser application's backend, a local identity provider,
> and the authenticated resource server. Open the printed application URL.

**Sources**

- Course — [Complete browser sign-in demo](../../samples/oidc-web-app/README.md)

### macOS: the same complete browser application

```bash title="bash or zsh - course-content root - one terminal"
npm --prefix samples/mcp-starter ci
npm --prefix samples/oidc-web-app ci
npm --prefix samples/oidc-web-app run demo
```

> **Key idea**
>
> Open the printed application URL, not a guessed port. The page is the interface;
> the backend is the OAuth client. Keep the launcher running until Ctrl+C.

### Try it as a student, then as the help desk

> **Key idea**
>
> Success means you return to a working page and see actual data. A callback
> connection error is not a completed sign-in. No external tenant is needed.

#### Viewer: "Is campus Wi-Fi down?"

1. Click **Sign in with course identity**
2. Use this run's synthetic viewer account
3. Read services and `INC-2026-0016`
4. Sign out; finish the provider prompt

#### Operator: "I can publish an update"

1. Sign in with the synthetic operator
2. Enter text, then **Review update**
3. **Confirm and publish**; see the timeline
4. Sign out, then Ctrl+C in the launcher

### Who can keep a client secret?

#### Public client

Browser code or an installed app is inspectable by its user.
An embedded secret cannot stay secret. Use PKCE, not a hidden password.

#### Confidential client

A backend can keep its credential on the server.
Our Backend-for-Frontend (BFF) is this OAuth client; the browser is its interface.
It still uses PKCE.

### The redirect's small pieces each have one job

| Piece | What your client does with it |
| --- | --- |
| Code | Short-lived, single-use exchange ticket; not an API credential |
| Verifier / challenge | Keep a random secret; send its one-way hash first |
| `S256` | SHA-256 (Secure Hash Algorithm, 256-bit) challenge method |
| `state` | Match callback to the pending login; resist cross-site request forgery (CSRF) |
| `nonce` | "Number used once": match the identity token to this login attempt |
| Bearer | Whoever possesses the access token can use it; keep it private |

### Fictional CampusPulse case: a stolen code is not yet a stolen token

#### Maya authorizes the client

- Scope requested: `campuspulse.read`
- The browser returns a short-lived code to the client
- Her password is entered only at the identity provider

#### Another app takes the code

- It has the code but not the client's random verifier
- The token endpoint rejects the mismatched PKCE proof
- `state` protects the client session; PKCE protects the code

### A study planner needs permission to read your timetable. It does not need your campus password, your grades, or permission to change your courses.

> A study planner needs permission to read your timetable. It does not need your campus password, your grades, or permission to change your courses.

— The sentence that makes OAuth make sense

### The problem was never "log in". It was "act on my behalf"

- A study planner needs **your timetable**, not your campus password
- Password sharing gives it whatever your whole account can do
- OAuth lets the provider grant **limited permissions and a token lifetime**
- You approve at the provider; later calls carry a token, not your password

> **Key idea**
>
> OAuth answers *"may this software do this specific thing to this resource on
> behalf of this person?"* It does not answer *"who is this person?"* That is
> OIDC, and confusing the two is the most expensive mistake in this unit.

### Four actors, and where trust stops

![Diagram of four OAuth actors. The resource owner uses a client. The client talks to an authorization server to get a token, and to a resource server to use it. A first trust boundary sits between the client and the authorization server, a second between the client and the resource server. The client is labelled untrusted.](../../assets/class-notes/week08-session-s18-1.svg)

*Four actors, two trust boundaries. Everything that goes wrong this week goes wrong at a boundary.*

### OIDC is a profile of OAuth, not a competitor

| | OAuth 2.x | + OpenID Connect |
| --- | --- | --- |
| Answers | may this app do X? | …and who is the user? |
| You get | `access_token` | …plus an `id_token` |
| Consumed by | the **API** | the **client**, once |
| Format | opaque **or** JWT | **always** a JWT |
| Metadata doc | RFC 8414 *(optional)* | OIDC Discovery *(optional)* |
| Claims (token fields) | format/profile-specific | issuer, subject, audience, expiry, issued-at |

**Sources**

- OpenID Foundation — [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- IETF — [RFC 8414, Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)

### Discover the provider's endpoints

```console title="abbreviated snapshot; use curl.exe in PowerShell"
$ curl -fsS https://accounts.google.com/.well-known/openid-configuration
{
 "issuer": "https://accounts.google.com",
 "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
 "token_endpoint": "https://oauth2.googleapis.com/token",
 "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
 "code_challenge_methods_supported": ["plain", "S256"]
}
```

> **Key idea**
>
> Start discovery from an issuer you trust. Read its endpoint addresses rather
> than guessing paths. In PowerShell use `curl.exe`; on macOS use `curl`.

### The keys are public, plural, and they rotate

```console title="fetched live, 2026-08-15 — signature verification material"
$ curl -fsS -D - https://www.googleapis.com/oauth2/v3/certs
cache-control: no-transform, public, must-revalidate, max-age=21144
{"keys":[
 {"kty":"RSA","alg":"RS256","use":"sig",
  "kid":"49900291d36cec8c018f2e8af3ef235b8b18d3c9", "e":"AQAB", "n":"..."},
 {"kty":"RSA","alg":"RS256","use":"sig",
  "kid":"8ff13a6fcdabf306712e58f35668a04eb5a5fae1", "...":"..."},
 {"kty":"RSA","alg":"RS256","use":"sig", "kid":"943a...7acba"},
 {"kty":"RSA","alg":"RS256","use":"sig", "kid":"f10f...c271"}]}
```

> **Key idea**
>
> This dated snapshot had four keys; today's count and values may differ.
> `kid` means key ID: match it, never choose the first key. PowerShell: `curl.exe`.

**Sources**

- IETF — [RFC 7517, JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517.html)

### Authorization Code with PKCE

### The flow you should default to, every time

![Sequence diagram with four columns: user agent, client, authorization server, resource server. The client generates a verifier and challenge, redirects the browser to the authorization server with the challenge, the user consents, an authorization code returns through the browser, the client posts the code plus the verifier to the token endpoint, receives an access token, and calls the resource server with it.](../../assets/class-notes/week08-session-s23-1.svg)

*Ten steps. The browser carries the code; only the client can spend it.*

### PKCE is four lines of arithmetic

```javascript title="samples/pkce.mjs — the mechanism"
import { createHash, randomBytes } from 'node:crypto';
const b64url = b => Buffer.from(b).toString('base64url');

const codeVerifier  = b64url(randomBytes(32)); // 43 chars, 256 bits
const codeChallenge = b64url(
  createHash('sha256').update(codeVerifier).digest());

// AUTH request: code_challenge + method=S256
// TOKEN request: code_verifier, over TLS, from your client only
```

> **Key idea**
>
> Run `node pkce.mjs` with the lab issuer running. Base64url makes URL-safe text;
> hashing makes a one-way fingerprint.

**Sources**

- IETF — [RFC 7636, Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)

### Inspect a request; test its exchange

#### Steps

1. `weeks/week08/samples` (`\` on Windows), course Node **24 LTS**
2. **A**: the *local* lab issuer `:9100` — not a real provider
3. **B**: PKCE, then negatives. Ctrl+C in Terminal A after

#### Expected observations

- URL builder: parameters only
- Exchange: one success, four refusals

#### Fallback

Use the offline transcript slide.

**Sources**

- Course — [Week 8 lab, Parts 0–2](lab.md)
- Course — [lab authorization server](samples/authz-server.mjs)

### Terminal A: the lab issuer

```powershell title="PowerShell - repository root - Terminal A"
cd weeks\week08\samples
node authz-server.mjs
```

> **Key idea**
>
> It binds to `127.0.0.1:9100`, prints its issuer, JWKS, and active `kid`, then blocks.

**Sources**

- Course — [lab authorization server](samples/authz-server.mjs)

### macOS: the lab issuer

```bash title="bash or zsh - repository root - Terminal A"
cd weeks/week08/samples
node authz-server.mjs
```

> **Key idea**
>
> It binds to `127.0.0.1:9100`, prints its issuer, JWKS, and active `kid`, then blocks.

**Sources**

- Course — [lab authorization server](samples/authz-server.mjs)

### Terminal B: build it, then break it

```powershell title="PowerShell - repository root - a fresh Terminal B"
cd weeks\week08\samples
node pkce.mjs
# Inspect the URL only: this helper has no callback server.

node pkce-negative.mjs
```

> **Key idea**
>
> `pkce.mjs` builds parameters. `pkce-negative.mjs` makes one successful exchange
> and four expected refusals. Use the browser demo for an actual sign-in.

**Sources**

- Course — [Week 8 lab, Part 2](lab.md)

### macOS: build it, then break it

```bash title="bash or zsh - repository root - a fresh Terminal B"
cd weeks/week08/samples
node pkce.mjs
# Inspect the URL only: this helper has no callback server.

node pkce-negative.mjs
```

> **Key idea**
>
> `pkce.mjs` builds parameters. `pkce-negative.mjs` makes one successful exchange
> and four expected refusals. Use the browser demo for an actual sign-in.

**Sources**

- Course — [Week 8 lab, Part 2](lab.md)

### A stolen code fails without the verifier

```console title="wrong verifier"
$ node pkce-negative.mjs
[A] code  lab_798601197cd070b880b5caacf6a80c5bc83aeb…

--- exchange with the WRONG code_verifier --------------------
HTTP 400
{ "error": "invalid_grant",
  "error_description": "PKCE verification failed",
  "expected_challenge": "z_1m6MhVmoJag5sEMKeOZYshyx…",
  "computed_challenge": "S8PQCZIMviVjOxZP2iqQH5p…" }
```

**Sources**

- IETF — [RFC 9700, OAuth 2.0 Security Best Current Practice §2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html)

### A failed exchange can burn the code

```console title="same code, now with the right verifier"
--- the RIGHT verifier, on that same code --------------------
HTTP 400
{ "error": "invalid_grant",
  "error_description": "unknown or already-redeemed code" }
```

> **Key idea**
>
> This server burns the code after any redemption attempt. RFC 7636 requires rejection; test whether your provider also revokes.

### What those failures prove

| What you saw | It proves | It does not prove |
| --- | --- | --- |
| `invalid_grant`, wrong verifier | **This** server enforces `S256` | Your provider does |
| `expected` vs `computed` shown | A teaching affordance | Real servers are this generous |
| Right verifier, code gone | This server burns the code | The RFCs require revocation |
| No-PKCE request refused | OAuth 2.1 behavior, here | Your tenant refuses it too |
| Every row above | A local model of a provider | Anything about your tenant |

**Sources**

- IETF — [RFC 7636 §4.6](https://www.rfc-editor.org/rfc/rfc7636.html)
- IETF — [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html)

### Offline path, then shut it down

```powershell title="PowerShell - repository root - no network needed"
Get-Content .\weeks\week08\samples\transcripts\part2-pkce-negative.txt
Get-Content .\weeks\week08\samples\fixtures\discovery-google.json

# Cleanup: Ctrl+C in Terminal A; close the consent browser tab
```

> **Key idea**
>
> The issuer's signing key lives in memory and dies with its process.

**Sources**

- Course — [captured PKCE negatives](samples/transcripts/part2-pkce-negative.txt)
- Course — [Google discovery snapshot, 2026-08-15](samples/fixtures/discovery-google.json)

### macOS: offline path, then shut down

```bash title="bash or zsh - repository root - no network needed"
cat ./weeks/week08/samples/transcripts/part2-pkce-negative.txt
head -n 40 ./weeks/week08/samples/fixtures/discovery-google.json

# Cleanup: Ctrl+C in Terminal A; close the consent browser tab
```

> **Key idea**
>
> The issuer's signing key lives in memory and dies with its process.

**Sources**

- Course — [captured PKCE negatives](samples/transcripts/part2-pkce-negative.txt)
- Course — [Google discovery snapshot, 2026-08-15](samples/fixtures/discovery-google.json)

### Five parameters, five different attacks

| Parameter | From | Checked by | Stops |
| --- | --- | --- | --- |
| `state` | client | client, on callback | **CSRF** |
| `code_challenge` | client | authz server | **code interception** |
| `nonce` | client | client, in the ID token | **ID token replay** |
| `resource` | client | authz server → `aud` | **reuse at another API** |
| `iss` | authz server | client, on callback | **provider mix-up** |

**Sources**

- IETF — [RFC 9700 §2.1, on `state`, PKCE, and `nonce`](https://www.rfc-editor.org/rfc/rfc9700.html)
- IETF — [RFC 9207, Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)

### Why the implicit flow died

#### What it did

- Asked for `response_type=token`
- Got an **access token in the URL fragment**
- No code, no token endpoint, no exchange

```text
#access_token=…
```

#### Why it is gone

- Tokens land in history and logs
- No client authentication, ever
- No refresh token, no requester binding

> **Failure to avoid**
>
> OAuth 2.1 removed it. So did MCP. Do not use it in new applications.

### Four easy mistakes, and how to avoid them

- **Hardcoding endpoints** instead of reading them out of the discovery document
- **`code_challenge_method=plain`**, because the provider advertises it and it works
- Reusing one `code_verifier` across requests — no error, no protection
- Skipping the `iss` check on the callback because "it worked"

> **Caution**
>
> Every one of these produces a **working login**. None of them produces a safe
> one. This is the delegation line from Week 1: the correctness oracle is not
> your compiler, it is a remote system with its own clock and its own operator.

### Fill in the four roles for your own MCP server — and say who holds what

1. Your MCP server is at `https://mcp.<yourname>.example/mcp`. Who is the **resource owner**, the **client**, the **authorization server**, and the **resource server**?
2. Which of them may hold a **client secret**, and why can the others not?
3. An attacker reads your browser history and finds `?code=…`. What else do they need, and where does it live?

**Sources**

- MCP — [Authorization, specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

## Block B — Claims and validation

### Tokens and claims — decoding is not validation

What is inside a token, who each claim is for, and the eight checks that stand between you and a forged one

You have a token. **Having one and being able to trust one are different problems.**

### Token vocabulary before we inspect one

| Term | Plain meaning |
| --- | --- |
| JSON Web Token (JWT, "jot") | A portable set of claims in JavaScript Object Notation (JSON) |
| Claim | A field asserting something; decoding does not make it true |
| `iss` / `sub` | Issuer / subject: who issued it / who it describes |
| `aud` | Audience: the intended recipient, not the person holding it |
| `exp` / `nbf` / `iat` | Expiration / not-before / issued-at, in Unix seconds |
| API / ID token | Application Programming Interface / identity token for the client |

### Why a JWT? A signed campus day pass

> **Key idea**
>
> Useful across independent services. Not automatically better for a one-server
> student app: a revocable server-side session is often simpler.

#### What the issuer writes

- Subject: this student
- Audience: this building, not every building
- Scope: enter the study room, not the server room
- Expiry: valid until a stated time

#### What the service can check

- The issuer signs the fields
- The service checks that signature locally
- It still checks the building, time and permission
- It need not phone the issuer on every request

### Fictional CampusPulse case: valid signature, wrong audience

#### What the client sends

- An ID token signed by the expected provider
- Issuer (`iss`) and expiration (`exp`) pass
- `aud` is `campuspulse-web`, the browser client

#### What the API decides

- The resource server expects **its own** audience, not the web client's ID
- It returns 401 before any incident data is read
- Decoding explains the token; validation decides whether to trust it here

### Three tokens, three jobs

| | Access token | ID token | Refresh token |
| --- | --- | --- | --- |
| Answers | may this app do X? | who signed in? | another access token? |
| `aud` names | the **API** | the **client** | n/a |
| Read by | resource server | client at sign-in | authorization server |
| Format | opaque **or** JWT | **always** JWT | usually opaque |
| Typical life | 5–60 min | minutes | days–months, rotating |
| Never | put it in a URL | use it as an API credential | send it to the resource API |

**Sources**

- IETF — [RFC 9068, JWT Profile for OAuth Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html)

### JWT or opaque: where is the decision data?

#### JWT — self-contained

- Verify with a cached JSON Web Key Set (JWKS)
- Local computation; no issuer call on a cache hit
- Claims stay fixed; signatures do not hide them

#### Opaque — a database handle

- Random handle; permissions live in a server record
- Introspection asks the issuer: active, and allowed what?
- Disabling the record works at the next fresh check
- Caching delays that revocation

**Sources**

- IETF — [RFC 7662, Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- IETF — [RFC 9068, JWT Profile for Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html)
- Curity — [The Phantom Token pattern](https://curity.io/resources/learn/phantom-token-pattern/)

### Alternatives: sessions and opaque tokens

#### Server-side session

- Cookie sends a random session identifier
- App looks up the user, permissions and expiry
- Delete the record to end the session
- One web app; replicas need shared state

#### Opaque OAuth access token

- Client presents a random token string
- API looks up or introspects permissions
- Revocation works at the next fresh check
- Delegation; the state service must be available

**Sources**

- OWASP — [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- IETF — [Token Introspection, RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)

### Other tools solve different identity problems

#### Campus single sign-on

**SAML:** Security Assertion Markup Language.
The provider sends signed **XML** (Extensible Markup Language).

The app validates the assertion, then creates a session.
Not a drop-in MCP access token.

#### Service access

**API key:** an issued secret identifying a calling service.
The API checks the key's record and permissions.

Useful for service identity, not user sign-in or delegated consent.
Protect and rotate the secret.

### A cookie and a JWT are not competing formats

- Browser to app: a **session-ID cookie**; the backend looks up the visit record
- Backend to API: a **JWT access token**; the API checks signature and permission
- A cookie carries a value; a JWT defines its format. They can work together

```shell title="Course-content root - reuse Block A's installed demo"
npm --prefix samples/oidc-web-app run demo
```

### How a signature protects readable claims

- Encode header and payload as base64url, a URL-safe text encoding
- Sign **encoded header + "." + encoded payload** with the issuer's private key
- Verify those exact bytes with the matching public key; it cannot mint tokens
- Change even one claim: the old signature no longer verifies
- Then check issuer, audience, time and permission; a valid signature is not enough

> **Key idea**
>
> Our RS256 format uses RSA (Rivest-Shamir-Adleman) signatures with SHA-256
> (Secure Hash Algorithm, 256-bit). Never place secrets in readable claims.

**Sources**

- IETF — [JSON Web Token, RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)
- IETF — [JWT Best Current Practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)

### Three segments, and one pointer that matters

![A JWT drawn as three joined boxes: header, payload, signature, separated by dots. An arrow runs from the kid field in the header to a JWKS document fetched from the issuer, and from there to the signature box, showing that the key identified by kid verifies the signature over the header and payload.](../../assets/class-notes/week08-session-s49-1.svg)

*Trust starts with your configured issuer; kid selects a key only from that issuer's trusted key set*

### A real access token, decoded

```console title="node validate-token.mjs --variant valid --decode-only"
header {"alg":"RS256","typ":"at+jwt","kid":"..."}
payload {
  "iss": "http://127.0.0.1:9100",
  "sub": "a4f1c0de-7c1b-4a2e-9f10-3d5c0b8e2a11",
  "aud": "http://127.0.0.1:8930/mcp",
  "exp": 1786824533, "iat": 1786823633,
  "scope": "openid campuspulse.read",
  "roles": ["viewer"]
}
```

> **Note**
>
> Run `node validate-token.mjs --variant valid --decode-only` with the lab issuer.
> This abbreviated snapshot is expired; new tokens work locally and need redaction.

### The claims that decide a request

| Claim | Means | Read by | If you skip it |
| --- | --- | --- | --- |
| `iss` | who minted it | resource server | any issuer's token works |
| `sub` | subject id; key by (`iss`, `sub`) | your app | users from different issuers collide |
| `aud` | who it is **for** | resource server | another API's token works here |
| `exp` `nbf` `iat` | expires / active after / issued at | resource server | stale or future tokens work |
| `scope` | what the **app** may do | resource server | no authorization at all |
| `roles` | what the **user** may do | your app | app and user rights conflated |

**Sources**

- IETF — [RFC 7519 §4.1, Registered Claim Names](https://www.rfc-editor.org/rfc/rfc7519.html)
- Descope — [nOAuth: an unverified `email` claim enabled account takeover](https://www.descope.com/blog/post/noauth)

### Decoding is not validation

### Decoding shows claims, not truth

#### What decoding proves

- The string was base64url
- It parsed as JSON

That is the complete list.

> **Caution**
>
> Decoding is a display operation, not a security operation.

#### What validation proves

1. `alg` is on **your** allow-list
2. `kid` resolves in the issuer's JWKS
3. the **signature** verifies
4. `iss` matches exactly
5. `aud` names **this** server
6. `exp` has not passed, allowing bounded clock drift
7. `nbf` / `iat` are not in the future
8. `scope` covers this operation

### Follow along: decode, then forge

#### Steps

1. Node **24 LTS**; course root = `instructor` in the master, or the student download root
2. **A**: the local lab issuer — it mints and serves the JWKS
3. **B**: decode, forge, check. Ctrl+C in Terminal A after

#### Expected observations

- Valid token: eight PASS, then ACCEPT 200
- Forged token: signature check fails

#### Fallback

Use the negative-battery fallback.

**Sources**

- Course — [Week 8 lab, Part 3](lab.md)
- Course — [the hand-written validator](samples/validate-token.mjs)
- Course — [All server/client commands and expected exit codes](samples/README.md)

### Terminal A: start the lab issuer

```powershell title="PowerShell - repository root - Terminal A"
cd weeks\week08\samples
node authz-server.mjs
```

> **Key idea**
>
> Expect the issuer, JWKS URL, and active key ID on port 9100. Reuse your issuer if already running.

**Sources**

- Course — [lab authorization server](samples/authz-server.mjs)

### macOS: start the lab issuer

```bash title="bash or zsh - repository root - Terminal A"
cd weeks/week08/samples
node authz-server.mjs
```

> **Key idea**
>
> Expect the issuer, JWKS URL, and active key ID on port 9100. Reuse your issuer if already running.

**Sources**

- Course — [lab authorization server](samples/authz-server.mjs)

### Terminal B: decode, then validate

```powershell title="PowerShell - repository root - a fresh Terminal B"
cd weeks\week08\samples
node validate-token.mjs --variant valid --decode-only

node validate-token.mjs --variant valid --scope campuspulse.read
```

> **Key idea**
>
> Two newly minted tokens of the same variant. Only validation makes a security
> claim; decoding just displays fields.

**Sources**

- Course — [the hand-written validator](samples/validate-token.mjs)

### macOS: decode, then validate

```bash title="bash or zsh - repository root - a fresh Terminal B"
cd weeks/week08/samples
node validate-token.mjs --variant valid --decode-only

node validate-token.mjs --variant valid --scope campuspulse.read
```

> **Key idea**
>
> Two newly minted tokens of the same variant. Only validation makes a security
> claim; decoding just displays fields.

**Sources**

- Course — [the hand-written validator](samples/validate-token.mjs)

### Change one claim, keep the signature

```powershell title="PowerShell - weeks\week08\samples - Terminal B"
node tamper.mjs                       # writes out\forged.txt

node validate-token.mjs --token-file out\forged.txt `
  --scope campuspulse.incident.write
```

> **Key idea**
>
> It rewrites `roles` to `["operator"]`, adds the write scope, and touches nothing else.

**Sources**

- Course — [tamper.mjs](samples/tamper.mjs)

### macOS: change one claim

```bash title="bash or zsh - weeks/week08/samples - Terminal B"
node tamper.mjs                     # writes out/forged.txt

node validate-token.mjs --token-file out/forged.txt \
  --scope campuspulse.incident.write
```

> **Key idea**
>
> It rewrites `roles` to `["operator"]`, adds the write scope, and touches nothing else.

**Sources**

- Course — [tamper.mjs](samples/tamper.mjs)

### Eight checks before acceptance

```console title="node validate-token.mjs --variant valid --scope campuspulse.read"
PASS  alg is on the allow-list           allowed=RS256
PASS  kid resolves in JWKS
PASS  signature verifies
PASS  iss matches configured issuer
PASS  aud contains this resource server
PASS  exp is in the future
PASS  nbf/iat are not in the future
PASS  scope includes campuspulse.read
ACCEPT 200
```

> **Key idea**
>
> After parsing: seven credential checks, then the permission check.
> The teaching validator displays every check, even after a failure.

### A perfectly valid token, correctly rejected

```console title="node validate-token.mjs --variant wrong-audience"
PASS  signature verifies
PASS  iss matches configured issuer
FAIL  aud contains this resource server
      token:    https://grades.campuspulse.example/api
      expected: http://127.0.0.1:8930/mcp
REJECT 401: audience mismatch
```

> **Failure to avoid**
>
> Nothing was forged. This lab token is signed correctly, but for a different
> service. A genuine library pass is not a server-room pass.

### Expired token or unknown key?

```console title="two more runs of the same validator"
--variant expired
  PASS  signature verifies
  FAIL  exp is in the future    delta=-2400s, skew=60s
  REJECT 401: token expired
--variant stale-kid
  FAIL  kid resolves in JWKS    kid=retired-2025-key
  REJECT 401: unknown signing key
```

> **Caution**
>
> Both are 401. Logs distinguish expired credentials from an unknown signing key;
> an unknown key can signal a stale cache or an untrusted token.

### An ID token presented to an API

```console title="node validate-token.mjs --variant id-token --scope campuspulse.read"
header  {"alg":"RS256","typ":"JWT","kid":"..."}
payload { "aud":"campuspulse-web", "nonce":"n-0S6_WzA2Mj", ... }
PASS  signature verifies
FAIL  aud contains this resource server
      The audience is the CLIENT, not the API.
FAIL  scope includes campuspulse.read    granted=[]
REJECT 401: audience mismatch
```

> **Failure to avoid**
>
> This genuine identity token is **not an API credential**. Audience and token
> purpose decide that, not whether the payload looks like a user profile.

### The negative battery, in one loop

```powershell title="PowerShell - weeks\week08\samples - Terminal B"
foreach ($v in 'expired','wrong-issuer','wrong-audience',
               'no-scope','id-token','stale-kid') {
  "===== $v ====="
  node validate-token.mjs --variant $v --scope campuspulse.read
}
Get-Content .\transcripts\part3-negatives.txt   # fallback capture
if (Test-Path .\out\forged.txt) {
  Remove-Item -LiteralPath .\out\forged.txt
} # Ctrl+C in Terminal A
```

**Sources**

- Course — [captured negative battery](samples/transcripts/part3-negatives.txt)

### macOS: the negative battery

```bash title="bash or zsh - weeks/week08/samples - Terminal B"
for v in expired wrong-issuer wrong-audience \
         no-scope id-token stale-kid; do
  printf '===== %s =====\n' "$v"
  node validate-token.mjs --variant "$v" --scope campuspulse.read
done
head -n 60 ./transcripts/part3-negatives.txt   # fallback capture
rm -f ./out/forged.txt                         # cleanup; Ctrl+C in A
```

**Sources**

- Course — [captured negative battery](samples/transcripts/part3-negatives.txt)

### Which check fired first

| Variant | First failing check | Status |
| --- | --- | --- |
| `expired` | `exp` is in the future | **401** |
| `wrong-issuer` | `iss` matches configured issuer | **401** |
| `wrong-audience` | `aud` contains this resource | **401** |
| `no-scope` | `scope` includes the required one | **403** |
| `id-token` | `aud` contains this resource | **401** |
| `stale-kid` | `kid` resolves in JWKS | **401** |

**Sources**

- IETF — [RFC 6750 §3, the `WWW-Authenticate` challenge](https://www.rfc-editor.org/rfc/rfc6750.html)
- Course — [captured negative battery](samples/transcripts/part3-negatives.txt)

### When the attacker picks `alg: none`

#### Token header

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

#### Failure mode

- Once treated as "verified with no key"
- Payload fully attacker-controlled
- No signature to check

> **Key idea**
>
> The token must not choose how it is verified. Run the local regression examples
> with `node --test identity.test.mjs` from `weeks/week08/samples`; they start and stop their own servers.

**Sources**

- Auth0 — [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- OWASP — [JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)

### A public key is not a shared secret

- **HMAC:** Hash-based Message Authentication Code; one shared secret
- HS256 uses HMAC with SHA-256; RS256 uses a private/public key pair
- The bug: verify an HS256 token using the published RSA public key as a secret
- The attacker knows that "secret" and can forge tokens
- Fix: allow only `algorithms: ['RS256']` for this issuer

> **Caution**
>
> `kid` picks only the key; never the algorithm.

**Sources**

- NIST NVD — [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (RS→HS confusion)

### What your validator must not do

- Do **not** trust `header.alg` — allow-list the algorithms in your config
- Do **not** fetch a key from a URL named inside the token (`jku`, `x5u`)
- Do **not** select a JWKS key by array index — select by `kid`
- Do **not** compare `iss` with normalisation — **exact string**, per RFC 9207
- Do **not** treat a missing `aud` as "must be for me"
- Do **not** set clock skew above ~60 seconds to make a flaky test pass

> **Caution**
>
> Every one of these makes tokens work. Several of them make *forged* tokens work
> too, and none of them produce an error message.

### What you actually write in production

- Use a maintained library; this course's Node reference uses `jose`
- Configure it with **your** issuer, **your** audience, **your** algorithm list
- Cache keys with a time to live (TTL); rate-limit refreshes on unknown `kid`
- Return **401** for authentication failures, **403** for authorization failures
- Log the **failed check name** and token identifier (`jti`) — never the token
- Sender binding can require a key too; it is separate from choosing JWT or opaque

> **Key idea**
>
> Keep the hand-written validator for learning. Use the maintained-library
> browser/server integration for your application.

**Sources**

- IETF — [RFC 6750 §3, the `WWW-Authenticate` challenge](https://www.rfc-editor.org/rfc/rfc6750.html)
- IETF — [RFC 9449, DPoP — sender-constrained tokens](https://www.rfc-editor.org/rfc/rfc9449.html)

### Beyond bearer: require the caller's key too

> **Key idea**
>
> These constrain who may present a token. Neither replaces JWT or opaque
> formats. Conceptual extension, not an additional classroom demo.

#### DPoP

**Demonstrating Proof of Possession.**
The client signs a proof for each request.
A token bound to that key cannot be used with the token alone.

#### mTLS

**Mutual Transport Layer Security.**
The client authenticates with a certificate during the encrypted connection.
The resource enforces the token's certificate binding.

### Four tokens arrive at your MCP server. Which status, and which check decided?

1. Signature valid · `iss` correct · `aud` = your **web API** · `exp` in 12 min
2. Signature valid · `aud` correct · `scope` = `openid profile` · no `campuspulse.*`
3. `alg: none` · payload says `"roles":["operator"]` · no signature segment
4. Signature valid · everything correct · `exp` was 90 seconds ago, skew is 60s

## Block C — Sessions and MCP auth

### Sessions, authorization decisions, and MCP auth

Where the token lives, where the decision belongs, and what OAuth looks like in front of the server you built last week

Block B ended with a token you can trust. **Now: where does it live, and who decides what it may do?**

### The browser-session vocabulary

#### Application pieces

- **SPA:** Single-Page Application; browser JavaScript renders the interface
- **BFF:** Backend-for-Frontend; a server handling identity and API calls for the browser
- **Session / cookie:** server's visit record / browser-stored value sent with requests

#### Boundaries to protect

- **XSS:** Cross-Site Scripting; unwanted code running in your page
- **CSRF:** Cross-Site Request Forgery; another site inducing a request with your cookies
- **MCP / AS:** Model Context Protocol / authorization server

### Fictional CampusPulse case: a visible tool can still be denied

#### Maya is a viewer

- Her client has `campuspulse.read`
- The host can still discover `post_incident_update`
- A model chooses that tool after she asks for a summary

#### The server owns the decision

- Required scope is `campuspulse.incident.write`
- Object policy also requires the operator role
- The server returns 403 and audits actor, tool, object, and reason

### Scopes and roles answer different questions

#### Scope — what the **app** may do

- Requested by the client, granted by **authorization-server policy**
- Lives in the token: `scope: "campuspulse.read"`
- Bounds the client, not the human
- Coarse by design — a handful, not hundreds

#### Role — what the **user** may do

- Assigned out of band, by an admin or a group
- Lives in `roles`, or in your database
- Bounds the human, not the client

> **Key idea**
>
> The effective permission is the **intersection** — an operator on a read-only
> client still may not post.

### Roles, attributes, and where to check them

- **Role-Based Access Control (RBAC):** is the user an operator?
- **Attribute-Based Access Control (ABAC):** assigned to this incident?
- Client checks help the interface, but an attacker can skip them
- Gateway checks control entry
- Resource-server checks protect the data and individual objects

> **Failure to avoid**
>
> A hidden React button improves the user experience; it is not a permission
> check. The server must also reject a request typed directly into a terminal.

### Where does the browser keep the token?

#### Token in the SPA

- `localStorage` — any script can read it
- In-memory — gone on refresh
- XSS can read tokens and make requests as the user

#### Backend-for-Frontend

- Tokens live **server-side**
- Browser gets a random session-ID cookie, not the token
- Local logout deletes the server's session record

> **Key idea**
>
> HttpOnly blocks cookie reading, not requests. A BFF reduces token theft,
> but does not make XSS harmless.

**Sources**

- OWASP — [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- MDN — [`Set-Cookie` and its attributes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)

### What the cookie settings actually do

- **HttpOnly:** page scripts cannot read the cookie
- **Secure:** send only over encrypted HTTPS
- **SameSite=Lax:** restrict cross-site sending; still use CSRF checks
- Sign in, reload, then sign out: the session survives reload but not local logout

```shell title="Course-content root - reuse Block A's installed demo"
npm --prefix samples/oidc-web-app run demo
```

> **Key idea**
>
> Block A's launcher starts client backend, provider and resource together.
> Its HTTP loopback mode uses a separate development cookie, never a production setting.

### Refresh, revoke, log out — three different things

- **Refresh:** exchange a refresh token for a new access token, ahead of `exp`
- **Rotation:** each refresh returns a *new* refresh token; the old one dies
  - Reuse can mean theft or a retry race; our provider **revokes the family**
- **Revocation:** RFC 7009 `/revoke` invalidates the token you present, and the AS *may* revoke related grants
- **Logout:** end your app's session; provider sign-out is a separate step

> **Caution**
>
> A JWT checked only offline can remain accepted until `exp` (plus clock tolerance).
> Earlier refusal needs a revocation check or policy lookup. Deleting the browser
> cookie alone does not revoke a copied token.

**Sources**

- IETF — [RFC 7009, Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html)
- OpenID Foundation — [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

### Six failures, and what catches each

| Failure | Symptom | Evidence that finds it |
| --- | --- | --- |
| Wrong audience | works, too widely | present another API's token → 401 |
| Wrong issuer | accepts the wrong tenant | signed `wrong-issuer` variant → 401 |
| Over-broad scope | one scope, every tool | scope-to-tool table + a denied call |
| **ID token as API token** | works, no `scope` exists | present the ID token → 401 |
| Missing PKCE | login works perfectly | wrong verifier → `invalid_grant` |
| Token in the URL | may leak through history/logs | HTTP Archive (HAR): `?access_token=` or `Referer` |

**Sources**

- IETF — [RFC 9700, OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)

### Authorizing the MCP server you built last week

### MCP does not invent an auth model. It profiles one.

- An HTTP MCP server using authorization follows an **OAuth resource-server** profile
- It **MUST** publish protected-resource metadata (RFC 9728)
- Clients **MUST** use Authorization Code + **PKCE**, and **MUST** send `resource` (RFC 8707)
- Servers **MUST** only accept tokens whose audience is themselves
- Servers **MUST NOT** accept or forward any other token — no passthrough
- `stdio` servers are excluded: they take credentials from the environment

> **Key idea**
>
> Every requirement above is something you already did in Blocks A and B. The MCP
> specification's contribution is making the discovery step mandatory so a client
> can find its way in without configuration.

**Sources**

- MCP — [Authorization, specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- IETF — [RFC 9728, Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)

### What you are adding to last week's system

![Architecture diagram. An MCP host and client on the left send requests to an authorization proxy on port 8930, which validates tokens against a JWKS from the authorization server on port 9100 and forwards allowed calls to the Week 7 MCP server on port 8931. The proxy publishes protected resource metadata and emits an audit log.](../../assets/class-notes/week08-session-s85-1.svg)

*One process added in front of the Week 7 server. The MCP server itself does not change.*

### Follow along: 401 → 403 → 200

#### Steps

1. Node 24 LTS; course root = `instructor` in the master, or student download root
2. **A** `:9100` issuer · **B** `:8930` proxy · **C** `:8931` server
3. **D** runs calls. Stop A, B, C with Ctrl+C

#### Expected observations

- No token: 401 with metadata pointer
- Viewer write: 403; operator write: 200

#### Fallback

Use the captured-walk fallback.

**Sources**

- Course — [Week 8 lab, Parts 0 and 5](lab.md)
- Course — [authorization proxy](samples/mcp-auth-proxy.mjs)
- Course — [Every server/client command and recovery step](samples/README.md)

### Terminals A and B: issuer and proxy

```powershell title="PowerShell - repository root in each new window"
# A:
cd weeks\week08\samples
$env:PORT='9100'; node authz-server.mjs
# B:
cd weeks\week08\samples
$env:MCP_UPSTREAM='http://127.0.0.1:8931/mcp'
$env:PORT='8930'; node mcp-auth-proxy.mjs
```

> **Key idea**
>
> Reuse your lab issuer if already running. Keep A and B open, then start C.

**Sources**

- Course — [Week 8 lab, Part 0](lab.md)

### macOS: issuer and proxy

```bash title="bash or zsh - repository root in each new window"
# A:
cd weeks/week08/samples
PORT=9100 node authz-server.mjs
# B:
cd weeks/week08/samples
PORT=8930 MCP_UPSTREAM=http://127.0.0.1:8931/mcp node mcp-auth-proxy.mjs
```

> **Key idea**
>
> `:8930` prints its policy table. Reuse a running issuer; keep A and B open, then start C.

**Sources**

- Course — [Week 8 lab, Part 0](lab.md)

### Terminal C: a memory-only backend

```powershell title="PowerShell - repository root - Terminal C"
cd samples\mcp-starter
npm ci                      # before class
npm run build               # before class
$env:MCP_HOST='127.0.0.1'; $env:PORT='8931'
$env:DATABASE_URL=$null
npm run start:http
```

> **Key idea**
>
> Expect `store=memory` and "NO AUTHORIZATION". Only the proxy adds the authorization boundary.

**Sources**

- Course — [starter quick start](../../samples/mcp-starter/README.md)

### macOS: a memory-only backend

```bash title="bash or zsh - repository root - Terminal C"
cd samples/mcp-starter
npm ci                      # before class
npm run build               # before class
MCP_HOST=127.0.0.1 PORT=8931 env -u DATABASE_URL npm run start:http
```

> **Key idea**
>
> `env -u DATABASE_URL` guarantees `store=memory`, so the operator's write stays synthetic.

**Sources**

- Course — [starter quick start](../../samples/mcp-starter/README.md)

### Terminal D: refusal and discovery

```powershell title="PowerShell - course-content root - fresh Terminal D"
cd weeks\week08\samples
$proxy = 'http://127.0.0.1:8930'
curl.exe --noproxy '*' -sS -i --max-time 10 "$proxy/mcp" -d "{}" `
  -H "content-type: application/json" -H "Mcp-Method: tools/call" `
  -H "Mcp-Name: post_incident_update" `
  -H "Mcp-Protocol-Version: 2026-07-28"
curl.exe --noproxy '*' -sS --max-time 10 `
  "$proxy/.well-known/oauth-protected-resource"
```

> **Key idea**
>
> Expect `401` with `WWW-Authenticate`: a metadata URL and scope `campuspulse.incident.write`.

**Sources**

- IETF — [RFC 9728, Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)

### macOS: refusal and discovery

```bash title="bash or zsh - course-content root - fresh Terminal D"
cd weeks/week08/samples
PROXY=http://127.0.0.1:8930
curl -sS -i --noproxy '*' --max-time 10 "$PROXY/mcp" -d '{}' \
  -H "content-type: application/json" -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: post_incident_update" \
  -H "Mcp-Protocol-Version: 2026-07-28"
curl -sS --noproxy '*' --max-time 10 \
  "$PROXY/.well-known/oauth-protected-resource"
```

> **Key idea**
>
> Expect 401 plus a `WWW-Authenticate` naming the metadata URL and the write scope.

**Sources**

- IETF — [RFC 9728, Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)

### Terminal D: three authenticated calls

```powershell title="PowerShell - weeks\week08\samples - keep A, B, C running"
node mcp-client-walk.mjs
node mcp-client-walk.mjs --tool post_incident_update
node mcp-client-walk.mjs --tool post_incident_update `
  --login-as operator
node mcp-client-walk.mjs --tool get_incident
```

> **Key idea**
>
> Read the incident again: the operator's fixed classroom update is public and
> visible. Viewer write is denied. HTTP 200 with a tool error is not success.

**Sources**

- Course — [local MCP authorization walk](samples/mcp-client-walk.mjs)
- Course — [real-provider integration and limits](provider-integration.md)

### macOS: three authenticated calls

```bash title="bash or zsh - weeks/week08/samples - keep A, B, C running"
node mcp-client-walk.mjs
node mcp-client-walk.mjs --tool post_incident_update
node mcp-client-walk.mjs --tool post_incident_update \
  --login-as operator
node mcp-client-walk.mjs --tool get_incident
```

> **Key idea**
>
> 401 → 403 → 200. Read the incident again to see the fixed synthetic update;
> the launcher commands keep all writes in memory.

**Sources**

- Course — [local MCP authorization walk](samples/mcp-client-walk.mjs)

### One missing token, three authenticated cases

| Run | Status | What decided it |
| --- | --- | --- |
| No token at all | **401** | No credential; challenge carries `resource_metadata` |
| Viewer, read tool | **200** | Granted scope covers `campuspulse.read` |
| Viewer, write tool | **403** | Tenant **refused to grant** the write scope |
| Operator, write tool | **200** | Scope granted **and** the `operator` role matched |
| Any of the four | — | None of them proves 8931 is protected |

**Sources**

- MCP — [Authorization, specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Course — [captured walks](samples/transcripts/part5-viewer-write-denied.txt)

### The handshake starts with a refusal

```console title="node mcp-client-walk.mjs — captured 2026-08-15"
[1] tools/call list_service_status, no token
    HTTP 401; challenge names resource_metadata and scope
[2] GET http://127.0.0.1:8930/.well-known/oauth-protected-resource
{
  "resource": "http://127.0.0.1:8930/mcp",
  "authorization_servers": ["http://127.0.0.1:9100"],
  "scopes_supported": ["campuspulse.read", "campuspulse.incident.write"],
  "bearer_methods_supported": ["header"]
}
```

> **Key idea**
>
> The 401 is the discovery starting point here: follow its protected-resource
> metadata (PRM) URL. Clients can also discover metadata via well-known paths.

### Per-tool scope, decided without parsing the body

```console title="spec 2026-07-28 requires the target in a header, not just the body"
Mcp-Method: tools/call
Mcp-Name: post_incident_update    # body must agree
Mcp-Protocol-Version: 2026-07-28

# Tool scope policy (writes also require operator role):
list_service_status   -> campuspulse.read
get_incident          -> campuspulse.read
draft_incident_update -> campuspulse.read
post_incident_update  -> campuspulse.incident.write
everything else       -> deny by default
```

> **Key idea**
>
> Header routing lets an intermediary route and rate-limit an MCP call **without**
> parsing JSON-RPC, and stops a caller showing the proxy one target while the
> server runs another. A careful proxy still parses the body to confirm they agree.

### The same call, one credential apart

```console title="node mcp-client-walk.mjs --tool post_incident_update"
# as a VIEWER — the tenant refused to grant the write scope at all
    scope         openid
[7] tools/call post_incident_update WITH the access token
    HTTP 403
    WWW-Authenticate: Bearer error="insufficient_scope",
      scope="campuspulse.incident.write",
      resource_metadata="http://127.0.0.1:8930/.well-known/…"

# as an OPERATOR — same client, same tool, same server
    scope         openid campuspulse.incident.write
[7] HTTP 200  {"result":{"content":[{"type":"text", …
```

> **Key idea**
>
> 401 → 403 → 200. Three different answers to the same request, and the only
> variable is the credential. That progression separates authentication from authorization.

### Where Week 7 and Week 8 actually collide

```console title="node expiry-mid-connection.mjs --ttl 6   (ENFORCE_STREAM_EXPIRY=0)"
t+  0s  stream opened: HTTP 200 text/event-stream
t+  0s  open        {"exp":1786824030,"expires_in":6,"enforcing":false}
t+  2s  heartbeat   {"n":1,"token_expires_in":4,"still_streaming":true}
t+  6s  heartbeat   {"n":3,"token_expires_in":0,"still_streaming":true}
t+  8s  heartbeat   {"n":4,"token_expires_in":-2,"still_streaming":true}
t+ 12s  heartbeat   {"n":6,"token_expires_in":-7,"still_streaming":true}

# with ENFORCE_STREAM_EXPIRY=1:
t+  8s  token_expired  {"error":"invalid_token",
                        "error_description":"re-authorize and reconnect"}
```

> **Failure to avoid**
>
> A `subscriptions/listen` stream takes **one** authorization decision, at open.
> An access token lives fifteen minutes. Minute 47 of that stream is serving data
> to a credential that expired half an hour ago — and your audit log's last entry
> still says `allow`.

### Terminal B: choose one stream mode

```powershell title="PowerShell - weeks\week08\samples - Terminal B only"
# Stop your proxy with Ctrl+C; run the bug mode:
$env:ENFORCE_STREAM_EXPIRY='0'; node mcp-auth-proxy.mjs
# AFTER Terminal D's bug run: Ctrl+C here, then:
$env:ENFORCE_STREAM_EXPIRY='1'; node mcp-auth-proxy.mjs
```

> **Key idea**
>
> Each server command blocks. Do not paste both starts together. Keep issuer A
> running; use D for the client while B holds the selected mode.

**Sources**

- Course — [captured bug run](samples/transcripts/part6-expiry-bug.txt)
- Course — [captured enforced run](samples/transcripts/part6-expiry-enforced.txt)

### Terminal D: measure both stream modes

```powershell title="PowerShell - weeks\week08\samples - Terminal D only"
# While B is in bug mode:
node expiry-mid-connection.mjs --ttl 6 --watch 14
# Switch B to enforced mode, then:
node expiry-mid-connection.mjs --ttl 8 --watch 22
Get-Content .\transcripts\part6-expiry-bug.txt
```

> **Key idea**
>
> Bug: heartbeats continue past expiry. Fix: token_expired and stream CLOSED.
> This is a synthetic Server-Sent Events (SSE) stream, not a full MCP subscription.
> Stop your A/B/C servers with Ctrl+C afterward.

### macOS B: choose one stream mode

```bash title="bash or zsh - weeks/week08/samples - Terminal B only"
# B: Ctrl+C, then restart the proxy with enforcement OFF
ENFORCE_STREAM_EXPIRY=0 \
  MCP_UPSTREAM=http://127.0.0.1:8931/mcp node mcp-auth-proxy.mjs
# B: Ctrl+C, then restart it enforced
ENFORCE_STREAM_EXPIRY=1 \
  MCP_UPSTREAM=http://127.0.0.1:8931/mcp node mcp-auth-proxy.mjs
```

> **Key idea**
>
> Run only one server command at a time. Use the next slide in D while B is
> running. After both measurements, Ctrl+C in your A, B and C windows.

**Sources**

- Course — [captured bug run](samples/transcripts/part6-expiry-bug.txt)
- Course — [captured enforced run](samples/transcripts/part6-expiry-enforced.txt)

### macOS Terminal D: measure both stream modes

```bash title="bash or zsh - weeks/week08/samples - Terminal D only"
# While B is in bug mode:
node expiry-mid-connection.mjs --ttl 6 --watch 14
# Switch B to enforced mode, then:
node expiry-mid-connection.mjs --ttl 8 --watch 22
head -n 40 ./transcripts/part6-expiry-bug.txt
```

> **Key idea**
>
> The first stream outlives its credential; the second emits token_expired and
> closes. This synthetic Server-Sent Events (SSE) test needs the issuer and proxy.

### Your MCP server has four tools. Write the policy table — and defend two rows.

1. `list_service_status` (read) · `get_incident` (read) · `post_incident_update` (writes) · `delete_incident` (destructive, added tomorrow)
2. Which scopes exist, and which tool needs which?
3. `delete_incident` ships tomorrow and nobody updates the table. What happens — and what *should* happen?

**Sources**

- MCP — [Scope selection and step-up authorization, spec 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

## Individual practice

### What you are doing in the next 35 minutes

- Walk an OIDC redirect with PKCE, then break it on purpose and read the error
- Validate a real token against a live JWKS; tamper with one claim; watch it fail
- Present wrong-audience, expired, and insufficient-scope tokens — read 401 vs 403
- Put the proxy in front of **your Week 7 MCP server** and watch `401 → 200`
- Deny a viewer's `post_incident_update`, then allow an operator's
- **Evidence:** redirect every terminal's output as you go — six of HW7's
  fourteen required artifacts are done before you leave the room

> **Caution**
>
> Four terminals: issuer (9100), proxy (8930), Week 7 server (8931), and client.
> Restarting the authorization server mints a **new**
> signing key, so every token issued before it is instantly stale.

## Homework brief

### HW7 — Claims Forensics and MCP Authorization

- **100 points**, due before Week 9 · satisfies **Gate 6 — Authorized**
- Prove — with transcripts, not assertions — that your validator rejects the
  tokens it should, and that your Week 7 MCP server now refuses unauthorized
  calls
- Deliverables: a sequence diagram from **your** provider's real endpoints,
  five negative-test transcripts, a claims matrix, and the MCP server behind
  OAuth with per-tool scopes and a captured denial
- Full handout: [`weeks/week08/homework.md`](homework.md)

> **Caution**
>
> Submitting a usable token is −20 and a mandatory resubmission with rotation
> evidence. Redact, do not crop — keep the shape.

## Closing logistics

### Before you leave

- **Exit ticket:** name one check your resource server performs that would
  still reject a genuine, correctly-signed, unexpired token from your own
  tenant — and say why that is not paranoia
- Revisit your HW6 attacker list. HW8 will test which attacks your
  authorization now blocks
- **Week 9 prep is posted** — next week attacks the system you just authorized
