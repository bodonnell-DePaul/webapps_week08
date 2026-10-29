# HW7 — Claims Forensics and MCP Authorization

**CSC 436 · Week 8 · Assigned in class, due before Week 9 · 100 points**

**No personal AI subscription required:** the
[HW7 supplied review draft](../../docs/non-ai-review-artifacts.md)
is an equally graded option for the challenged claim. Cite the supplied draft,
not an invented personal AI exchange.

**Required route: 8–10 hours with the provisioned tenant and Week 7 starter.**
Read [the provider integration checklist](provider-integration.md) first.
The [supported browser OIDC/BFF baseline](../../samples/oidc-web-app/README.md)
provides the maintained client, callback, session and authenticated application
path. Reuse it; do not spend the assignment writing your own OIDC protocol.
Its real local-provider demo is preparation, while the assigned tenant's
observations remain separately labeled.
Use the shared [authenticated HTTP entry](../../samples/mcp-starter/AUTHENTICATED-HTTP.md)
for the actual MCP resource server. Keep the `campuspulse.*` teaching-proxy
scope profile separate from its `status:read` / `incidents:read` /
`incidents:write` production-integration profile.
Reuse lab negatives, your existing App, and the same evidence in the final;
do not build a second authorization layer. Environment/provisioning failures
must be labeled, not disguised with local fixture transcripts.

> **The point of this assignment, in one sentence:** prove — with transcripts, not
> assertions — that your identity layer rejects the tokens it should reject, and
> that the MCP server you built last week now refuses the calls it should refuse.

---

## 1. Where this fits

| | |
| --- | --- |
| **Satisfies** | **Gate 6 — Authorized** on the final project. OIDC login working; operator vs. viewer roles enforced; MCP server behind OAuth with per-tool scopes. |
| **Builds on** | HW6 (at least three read tools and one confirmed action) and your Week 7 "what an attacker could currently do" list. |
| **Feeds** | HW8 (Week 9) attacks this exact system. Your audit log and policy table become Week 9 inputs. Half your Week 7 attacker list should be false by the time you submit this. |

You are not building a new system. You are **authorizing the one you have**, and
documenting what you can now prove about it.

---

## 2. Prerequisites

Before you start, all of these must be true:

- [ ] Your **Week 7 MCP server runs**, with at least three read tools and exactly
      one confirmation-gated action, plus the working feed/App required at Gate 5.
- [ ] You have your **client registration** in the course OIDC tenant, plus the **separate MCP client registration** with its own audience. (URLs and client IDs: [`README.md`](README.md).)
- [ ] You know your tenant's **viewer** and **operator** test-user credentials.
- [ ] You have completed the **Week 8 lab** — the transcripts it produces are 6 of the 14 required artifacts.
- [ ] Node.js 24 LTS for course scripts; production library in your chosen stack.

> **If your Week 7 server does not run**, fix that first and say so in your AI-use
> log. `MCP_UPSTREAM=stub` unblocks the lab but **does not** satisfy Task 6 — Task 6
> requires your own server behind OAuth.

---

## 3. Tasks

### Task 1 — Map your provider's actual flow (8 pts)

1. Fetch your tenant's discovery document and save it:
   ```bash
   curl -s "$TENANT/.well-known/openid-configuration" > evidence/01-discovery.json
   ```
2. Draw a **sequence diagram** of Authorization Code + PKCE using **your provider's
   real endpoint URLs** — copied from that document, not from a tutorial. Mermaid,
   draw.io, or clean hand-drawing all acceptable.
3. Label on the diagram where `state`, `nonce`, `code_challenge`, `code_verifier`,
   `resource`, and `iss` each appear, and **which party checks each one**.
4. Write one paragraph: name **two fields in your discovery document that surprised
   you**, and say what each one commits your provider to.

> A diagram with `https://authserver.example/authorize` on it scores zero for this
> task. The point is that you read *your* provider's configuration.

### Task 2 — Capture the code exchange with PKCE visible (8 pts)

1. Use the supported BFF's sign-in flow, which constructs and stores the
   state/nonce/PKCE transaction. The hand-run helper in
   [provider integration](provider-integration.md) is an optional protocol
   diagnostic, not a replacement for application login.
2. Run the redirect **in a browser with DevTools recording**, Preserve log on.
3. Export the HAR. **Sanitize it** — see §5 — and save as `evidence/02-authorize.har`.
   Use the final filename `evidence/03-authorize.har`. In your write-up, quote the request line showing `code_challenge=` and
   `code_challenge_method=S256`.
4. **The token request is a separate artifact.** It is a direct server-to-server
   call in a BFF and will not appear in that browser HAR; a public SPA may make
   it in the browser. Record which architecture you tested. Capture it with
   `curl -v` (or your client's log) and save the sanitized transcript as
   `evidence/02b-token-exchange.txt`, showing `code_verifier=` and `resource=`.

   ```bash
   curl -sv -X POST "$TOKEN_ENDPOINT" \
     -d grant_type=authorization_code \
     -d code="<CODE>" \
     -d redirect_uri="<YOUR_REDIRECT_URI>" \
     -d client_id="$CLIENT_ID" \
     -d code_verifier="<VERIFIER>" \
     -d resource="$MCP_RESOURCE" 2>&1 | tee 02b-token-exchange.raw.txt
   ```

   > **If your client is confidential**, it must also authenticate — add
   > `-u "$CLIENT_ID:$CLIENT_SECRET"` (HTTP Basic, RFC 6749 §2.3.1). **The secret
   > must not appear in the submitted transcript**: redact the `Authorization:
   > Basic …` line, and say in your write-up which authentication method you used.
   > If your tenant also has a public/native client registered for
   > `http://127.0.0.1:5173/callback`, use that instead and say so — a public
   > client with PKCE is the correct shape for a hand-run flow.

5. **Negative test:** exchange a code with a deliberately wrong `code_verifier`.
   Capture the full error body in `evidence/04-pkce-negative.txt`. Explain in two
   sentences what an attacker who stole your authorization code can do with it,
   and why.
6. **Then answer one question with evidence:** after a *failed* exchange, does
   your provider still accept the correct verifier for that same code, or was the
   code consumed? Both behaviours occur in the wild. RFC 7636 §4.6 only requires
   rejection; RFC 9700 §2.1.1 pushes toward revocation. **Test it and say which
   yours does.**

### Task 3 — The claims matrix (10 pts)

Obtain **both** an access token and an ID token from your tenant for the same
login. Decode both. Produce a table with **one row per claim that appears in
either token**:

| Claim | In access token | In ID token | Value (redacted) | What it means | **Who consumes it** | What breaks if you ignore it |
| --- | --- | --- | --- | --- | --- | --- |
| `iss` | ✔ | ✔ | `https://…` | issuer identity | resource server **and** client | any issuer's tokens are accepted |

Cover at minimum: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `azp`, `scope`,
`roles` (or your provider's equivalent), `amr`, `nonce`, and your authorization
custom claims. Mark absent optional claims **absent**, with what that means;
do not invent `nbf`, `azp`, `roles` or `amr`. For an opaque access token, use
the provider's documented introspection output instead of trying to decode it.

Then answer, in prose:

- Which claims appear in **only one** of the two tokens, and why that is correct.
- What your API would lose if it accepted the ID token instead of the access token.

> **This is the highest-value task in the assignment.** It is also the one students
> most often submit as a bare list of claim names with dictionary definitions. The
> graded columns are **"who consumes it"** and **"what breaks"**.

### Task 4 — Validation, proven (10 pts)

Implement token validation in **your own resource server**, in your own language.
You may use a maintained library (`jose`, `python-jose`,
`Microsoft.IdentityModel.Tokens`, `github.com/lestrrat-go/jwx`, …) — you are graded
on the configuration and the evidence, not on hand-rolled cryptography.

Submit:

1. Your validation configuration — issuer, audience, **algorithm allow-list**,
   clock skew, JWKS caching policy — as committed code or config, with the file
   path and line numbers.
2. Output showing **all** of these checks passing on a good token: signature,
   issuer, audience, expiry.
3. **Five negative tests**, each with the request, the response status, the
   `WWW-Authenticate` header, and one sentence of diagnosis:

| # | Token presented | Required status |
| --- | --- | --- |
| 4a | expired | 401 |
| 4b | wrong issuer | 401 |
| 4c | wrong audience | 401 |
| 4d | tampered payload, original signature | 401 |
| 4e | valid, but missing the required scope | **403** |

4. A short paragraph: **why 4c is a 401 and 4e is a 403.** Getting this backwards
   is diagnosed here; the same defect is not deducted twice at the gate.

> Use the course tenant's wrong-audience test user for 4c, or the lab
> authorization server's `/mint?variant=wrong-audience`. The CLI flag belongs
> to `validate-token.mjs`, not `authz-server.mjs`. Say which issuer you tested.
> For local negatives configure a separate test validator to trust the local
> issuer/JWKS: otherwise every fixture just fails signature/issuer, not the
> intended audience/expiry check. Never add the lab issuer to production trust.

### Task 5 — Session handling (6 pts)

1. State which session architecture your app uses — **token-in-memory SPA** or
   **Backend-for-Frontend** — and justify it **against a threat**, not a preference.
   One paragraph. "The tutorial did it" is not a justification.
2. If you use cookies: paste the actual `Set-Cookie` header and annotate every
   attribute.
3. Evidence for all three of:
   - a **refresh** happening (before/after `exp`, or the token response)
   - **logout** — and what is still true afterwards
   - **expiry** — a request that succeeds, then the same request after `exp`, with statuses
4. One sentence: after logout, how long can an already-issued access token still
   be used against your API, and what would you change to shorten that?

### Task 6 — Your MCP server behind OAuth (14 pts)

This is the assignment's centre of gravity.

1. **Publish protected-resource metadata.** Follow the exact `resource_metadata`
   URL in the 401 challenge and paste its JSON and URL. The authenticated
   starter defaults to `/.well-known/oauth-protected-resource/mcp`; the local
   teaching proxy also serves a root-level demonstration document.
2. **The 401 → authorized progression.** One transcript showing, in order:
   - the tool call with no token → **401** with a `WWW-Authenticate` carrying `resource_metadata`
   - the PRM fetch
   - the authorization-server metadata fetch
   - the token request (PKCE + `resource`)
   - the same tool call with the token → **200**
3. **Per-tool scope enforcement.** Submit your **policy table** — every tool, its
   required scope, and the **default for an unlisted tool**. Then capture:
   - a **denied** call: a genuine token without the write scope invoking your
     state-changing tool → **403** with `error="insufficient_scope"`
   - the **same call** with an operator token carrying write scope → **200**
   - write scope without operator role → **403**, and operator with read-only
     scope → **403**. Use `viewer-write` and `operator-read` local variants
     for these independent policy tests, labeled as local.
4. **Audience binding verified.** Present a token whose `aud` names a *different*
   resource and show it rejected. State where the `resource` parameter is sent and
   what your `aud` value is.
5. **Expiry on a long-lived connection.** Open a long-lived connection
   (`subscriptions/listen`, SSE, or WebSocket — whatever your Week 7 system uses),
   let the token expire, and **document what actually happened**. If the connection
   survived its own credential, say so and describe your fix. Both the observed
   behaviour and the fix are graded; only "we did not test it" scores zero.
6. **Audit log.** At least ten lines in the form
   **actor → tool → arguments-shape → decision → result**, including at least one
   `deny`. No tokens in the log; use `jti` or a hash.

### Task 7 — Provider configuration, sanitized (4 pts)

Export your client registration(s) — web client and MCP client — as **JSON with
every secret replaced by `<REDACTED:client_secret>`**, or as a screenshot with
secrets visibly blacked out. Must show: client id, redirect URIs, grant types,
PKCE requirement, the scopes defined, and the audience/resource identifier.
Also state what blocks direct access to the unauthenticated upstream. A local
stub/proxy demonstration is not evidence that this deployment boundary is safe.

> Prefer the JSON form — it is what the redaction attestation in §4 is written
> for, and a blacked-out screenshot cannot be machine-scanned.

### Task 8 — The eight-part evidence standard (40 pts)

Every submission carries all eight parts. See §4.

---

## 4. Required evidence artifacts

Submit **all fourteen**, in an `evidence/` directory, named as shown:

| # | File | From |
| --- | --- | --- |
| 01 | `01-discovery.json` | Task 1 |
| 02 | `02-sequence-diagram.(png\|svg\|md)` | Task 1 |
| 03 | `03-authorize.har` **(sanitized)** + `02b-token-exchange.txt` **(sanitized)** | Task 2 |
| 04 | `04-pkce-negative.txt` | Task 2 |
| 05 | `05-claims-matrix.md` | Task 3 |
| 06 | `06-validation-config.md` (path + line refs + excerpt) | Task 4 |
| 07 | `07-validation-pass.txt` | Task 4 |
| 08 | `08-validation-negatives.txt` (4a–4e) | Task 4 |
| 09 | `09-session.md` + `09-session-evidence.txt` | Task 5 |
| 10 | `10-protected-resource-metadata.json` | Task 6.1 |
| 11 | `11-401-to-200.txt` | Task 6.2 |
| 12 | `12-scope-policy.md` + `12-denied-then-allowed.txt` | Task 6.3 |
| 13 | `13-audience-binding.txt` | Task 6.4 |
| 14 | `14-expiry-mid-connection.md` + transcripts | Task 6.5 |
| — | `audit.jsonl` | Task 6.6 |
| — | `client-config.json` (redacted) | Task 7 |
| — | `README.md` — your annotated write-up | all |

### The eight-part evidence standard

Restated from [`docs/evidence-standard.md`](../../docs/evidence-standard.md):

1. **Commit SHA or release tag** of exactly what was tested.
2. **Reproduction commands** plus exported config.
3. **Raw sanitized evidence** — HAR, header dumps, JSON-RPC transcripts.
4. **Annotated interpretation** in your own words.
5. **At least one deliberate failure** and its diagnosis. *(Tasks 4 and 6 give you five.)*
6. **AI-use log** — generated, accepted, rejected, and how you verified.
7. **One challenged AI claim**, consequential, with the evidence that rejected it.
8. **Redaction attestation** — see below. **Mandatory this week.**

### The redaction attestation (mandatory)

Include this, in your own words, in `evidence/README.md`:

> I attest that no artifact in this submission contains a usable credential. All
> access tokens, ID tokens, refresh tokens, authorization codes, client secrets,
> cookies, and `code_verifier` values have been replaced with typed placeholders
> preserving their shape. Any token that appears in decoded form is expired and
> was issued by the course lab authorization server, whose signing key does not
> persist. I have verified this by scanning the submission with
> `<the command you ran>`.

**Replace, do not crop.** Keep the shape:

```text
Authorization: Bearer <REDACTED:access_token 1043 chars, RS256, exp 2026-08-15T19:13:53Z>
```

The shape is often the evidence. A blacked-out rectangle proves nothing.

> **Submitting a usable token** is an automatic zero on that artifact plus a
> mandatory resubmission with rotation evidence. Rotating a leaked credential is
> itself a graded skill — this is a policy, not a threat.

---

## 5. Sanitizing evidence

A HAR from an OAuth flow contains, at minimum: the authorization code (in a URL),
the token response body, session cookies, and sometimes the `code_verifier`. It
hides in five places — **URLs, query-string arrays, headers, cookie arrays, and
bodies** — so a sanitizer that only walks one of them is worse than none, because
it produces false confidence.

**Work in a directory git will never see.** Add these to your `.gitignore`
*before* you capture anything:

```gitignore
raw-evidence/
weeks/week08/samples/out/
*.raw.har
*.raw.txt
```

Capture into `raw-evidence/`, sanitize **into** `evidence/`, and never move a raw
file by hand.

```bash
node weeks/week08/samples/sanitize-har.mjs raw-evidence/authorize.har evidence/03-authorize.har
```

A working sanitizer is provided at
[`samples/sanitize-har.mjs`](samples/sanitize-har.mjs). Read it before you run it —
you are responsible for what it misses.

Then **verify**, twice. First a shape scan:

```bash
grep -REn 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' evidence/ \
  && echo "STILL LEAKING" || echo "no JWTs"
```

```powershell
Get-ChildItem evidence -Recurse -File |
  Select-String -Pattern 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
```

A shape scan is **not sufficient** — it does not catch opaque tokens,
authorization codes, or client secrets, none of which look like a JWT. So second,
scan for the **actual values** you handled:

```bash
node weeks/week08/samples/scan-evidence.mjs evidence/ --secrets-from raw-evidence/known-values.txt
```

`known-values.txt` is a file you write, one secret per line, listing every code,
token, verifier, cookie, and secret that passed through your terminal during the
assignment. It is gitignored. If the scanner finds any of them under `evidence/`,
you are not done.

**Paste the output of both checks into your attestation.**

---

## 6. Worked example — what Task 3 depth looks like

**Insufficient** (this is what most first drafts look like, and it scores ~3/15):

> | Claim | Meaning |
> | --- | --- |
> | `aud` | audience |
> | `azp` | authorized party |
> | `amr` | authentication methods |

**Sufficient** (excerpt — three rows at the expected depth):

> | Claim | Access | ID | Value (redacted) | Meaning | Who consumes it | What breaks if ignored |
> | --- | --- | --- | --- | --- | --- | --- |
> | `aud` | ✔ | ✔ | AT: `api://campuspulse-mcp`  ID: `f81d…-web` | The party this token was minted **for**. Different value in each token — the access token names our MCP resource server, the ID token names our web client. | AT: our MCP server, on every request. ID: our React client, once, at login. | Our MCP server would accept tokens issued for our **grades API**, which carries a broader scope. Our per-tool policy would be bypassable by obtaining a grades-API token instead. Verified: `evidence/13-audience-binding.txt` shows a grades-audience token rejected 401. |
> | `azp` | ✔ | — | `campuspulse-mcp-client` | Which **client** requested this token, as distinct from which user it represents. Present because our tenant issues to two clients against one audience. | Our MCP server, for audit correlation — not for the authorization decision. | We could not tell, in the audit log, whether a write came from the web app or from a model in an MCP host. That distinction is the whole of the Week 9 confused-deputy discussion. |
> | `amr` | ✔ | ✔ | `["pwd"]` for viewer, `["pwd","mfa"]` for operator | How the subject authenticated in this session. | Our MCP server, for one tool only. | `delete_incident` could be invoked by a session that never did MFA. We enforce `amr ∋ "mfa"` for that tool and return 403 with a step-up challenge otherwise — see `evidence/12-scope-policy.md` row 4. |

Notice what makes the second version pass: **a real value, both token columns
filled in, the consumer named, a specific consequence, and a cross-reference to
the artifact that proves it.**

### And what Task 6.5 depth looks like

**Insufficient:** *"The token expires and the user has to log in again."*

**Sufficient:**

> Our Week 7 feed uses `subscriptions/listen` (a single long-lived POST stream).
> Our first implementation validated the bearer token when the stream opened and
> never again. We minted a 6-second token, opened the stream, and captured 14
> seconds: the stream was still emitting at `token_expires_in: -6`
> (`evidence/14-expiry-bug.txt`). The audit log's last entry
> for that stream was `"decision":"allow"` — so a revoked operator would have kept
> receiving incident data with **no further log line**, which is worse than the
> data leak.
>
> Fix: the proxy now records `exp` at stream open and arms a timer; on fire it
> emits `event: token_expired` and closes, logging
> `"decision":"terminate","reason":"token_expired_mid_stream"`
> (`evidence/14-expiry-fixed.txt`). We chose termination
> over in-band re-authorization because our client already reconnects with backoff
> (HW6 §4), so the cost is one reconnect.
>
> My stated expiry behaviour is termination at `exp`. **Residual risk we
> are accepting:** this bounds exposure to at most one token lifetime; it does
> **not** detect revocation. A user revoked at minute 2 keeps receiving data until
> minute 15. Closing that gap needs either a shorter access-token lifetime or an
> on-stream revocation check, and we have done neither, because our reconnect
> storm budget (HW6) assumes ≤ 4 reconnects/hour/client.

---

## 7. Rubric (100 points)

| # | Criterion | Pts |
| --- | --- | ---: |
| 1 | **Provider flow mapped** — real endpoints, six parameters located, two surprising fields explained | 8 |
| 2 | **Code exchange** — real flow, PKCE and code-consumption negative | 8 |
| 3 | **Claims matrix** — present/absent claims, consumer and consequence | 10 |
| 4 | **Validation** — configuration, positive path, five correctly isolated negatives | 10 |
| 5 | **Sessions** — actual refresh/logout/expiry, architecture explained | 6 |
| 6 | **MCP authorization** — metadata/progression (4), independent scope/role (4), audience (2), stream lifetime (2), audit (2) | 14 |
| 7 | **Provider config and direct-origin boundary** | 4 |
| 8 | **Evidence standard** — eight parts at 5 points each | 40 |
| — | **Total** | **100** |

**Deductions**

| | |
| --- | --- |
| Any usable credential in the submission | Zero for the affected artifact and resubmission with rotation evidence; no duplicate blanket deduction |
| Missing redaction attestation | −5 |
| A negative test asserted but not evidenced | −4 each |
| Diagram or transcripts from the lab tenant where the task requires **your** provider | −5 each |

---

## 8. Time estimate

Individual work. These are **your hours**, not a split with anyone else.

| Task | Hours |
| --- | ---: |
| 1–3 — One provider walk and annotated claims | 2–3 |
| 4 — Reuse local negative transcripts; verify real positive configuration | 1–1.5 |
| 5–6 — Integrate existing server, roles/session checks, reuse stream experiment | 3–3.5 |
| 7–8 — Export, redact and index existing evidence | 2 |
| **Total** | **8–10 hours** |

This assumes the instructor has delivered functioning registrations and an
integration baseline for your stack. Do not spend these hours reverse-engineering
tenant administration. If blocked, submit the exact failed step and continue
the diagnostic tasks; recover the real-provider gate with the instructor.

**Task 6 is where students lose control**, and Task 4 is second. Both depend on
things outside your editor — a tenant that has to be configured, a token that has
to actually expire. Start Task 6 the day it is assigned.

> **A shortcut that is not cheating.** Tasks 4 and 6 need *deterministic* bad
> tokens: expired, wrong-issuer, wrong-audience, and one missing a scope. Your
> real tenant will not mint those on demand. Use the lab authorization server
> (`GET /mint?variant=…` on the running local issuer) as a **fixture generator** for those
> cases, point your validator at its issuer and JWKS for that test run, and say
> so in your write-up. The *positive* path and the audience-binding evidence must
> still come from your real tenant.

> **If your Week 7 system has no long-lived stream** — no `subscriptions/listen`,
> no SSE, no WebSocket — Task 6.5 becomes: open any connection or session that
> outlives one token lifetime (a polling client holding a token, a queued job, a
> retry loop) and document what happens at `exp`. If you genuinely have nothing
> that outlives a token, say so with evidence and describe what you *would* do.
> Full marks are available for a well-argued "not applicable here, and here is
> why".

---

## 9. What good looks like vs. what loses points

| What good looks like | What loses points |
| --- | --- |
| "The token was rejected with 401 and `error_description="audience mismatch"`; the `aud` was `api://campuspulse-grades` and our resource identifier is `api://campuspulse-mcp`." | "Audience validation is enabled." |
| A HAR with `<REDACTED:access_token 1043 chars>` preserving the field | A HAR with a black rectangle over a screenshot |
| A policy table with an explicit **deny-by-default** row | Fourteen `if` statements pasted from the handler |
| "Our stream survived its own token by 6 seconds; here is the capture and here is the fix." | "Token expiry is handled." |
| "The model produced `jwtVerify(token, key)` with no `algorithms` option; we rejected it and added an allow-list — here is the `alg: none` test that proves it now fails." | "We used AI to write the validation code." |
| Annotations in your own words, explaining the reasoning behind each finding | A write-up that reads like generated boilerplate with no reasoning shown |

---

## 10. The environment-bound component

**Be precise about this, because a coding agent with a terminal really can run
these tests for you.** The claim is not "a model cannot produce these bytes." The
claim is narrower and harder:

> These artifacts are **environment-bound evidence**, not code-generation tasks.
> They are valid only if they are reproducible from your tagged commit, against
> your tenant, and defensible by you in conversation.

Three things here have no correct answer that exists outside your own system:

1. **The negative results.** No model has seen your tenant, your audience string,
   or your clock. It can produce a *plausible* transcript — and a plausible
   transcript that does not match your tagged commit is **fabricated evidence**,
   which goes through the University integrity process rather than a grade appeal.
   The defence against that temptation is that it is trivially checkable: the
   grader re-runs your reproduction commands.

2. **The scope-to-tool policy table.** This encodes which of *your* tools change
   state, which are destructive, and what your project means by "operator". That
   is a design judgment recorded in your Week 7 work and your head. A model can
   guess a table; it cannot know that `draft_incident_update` is safe in your
   system because it never publishes, or that your `delete_incident` is soft.

3. **The expiry-on-a-long-lived-connection result.** An empirical fact about the
   interaction between two things you built in two different weeks. The only way
   to know it is to run it and watch a number go negative.

**Yes, you may use an agent to run the tests.** Log it in your AI-use log like
anything else. What you may not do is submit output you did not produce, or
cannot explain. The oral component of the final project is where that gets
checked.

---

## 11. Submission

- Push to your repository on a branch named `hw7-claims-forensics`.
- Tag the commit you tested: `git tag hw7-submission && git push --tags`.
- Submit in D2L: the repository URL, the **tag name**, and the **commit SHA**.
- `evidence/README.md` is the front door. It must link every artifact and contain
  the redaction attestation.

**Due before Week 9.** Week 9's lab attacks this system; if it is not authorized,
you will spend that lab building instead of attacking.

---

## Reference

- [Week 8 lab](lab.md) · [lecture notes](class-notes.md) · [prep](prep.md)
- [Evidence standard](../../docs/evidence-standard.md) · [AI-use policy](../../docs/ai-use-policy.md)
- [MCP — Authorization, spec 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [RFC 9728 — Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html) · [RFC 8707 — Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636.html) · [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 6750 — Bearer tokens and `WWW-Authenticate`](https://www.rfc-editor.org/rfc/rfc6750.html) · [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519.html)
