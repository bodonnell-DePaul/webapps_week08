# Week 8 — Pre-Class Prep (~55 min)

**CSC 436 · Identity: OAuth, OIDC, Claims — and Authorizing the MCP Server**

> **Due before class.** The opening includes short retrieval, a focused
> readiness-check debrief, and weekly logistics. Block A's teaching assumes
> you have already inspected a discovery document yourself.

---

## Why this prep exists

You are about to put OAuth in front of the MCP server you built last week. Almost
all of the hard part is vocabulary and shape: four actors, three token types,
about a dozen claims, and one flow. Reading it cold in a lecture is a waste of
lecture. **Read it here so class can be spent on the parts that break.**

The one hands-on item (item 3) takes five minutes and makes the whole of Block A
concrete. Do not skip it.

---

## Core set (~55 min) — all required

| # | Title | Publisher | Type | Time |
| --- | --- | --- | --- | ---: |
| 1 | [OAuth 2.0 Simplified](https://aaronparecki.com/oauth-2-simplified/) — roles and code flow only | Aaron Parecki | Article | 15 min |
| 2 | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — **§1–3 only** | OpenID Foundation | Spec | 15 min |
| 3 | [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) — **§4**, plus the hands-on below | OpenID Foundation | Spec | 5 min |
| 4 | [jwt.io](https://jwt.io/) — decode a token | Auth0 | Interactive | 5 min |
| 5 | [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636.html) — **§1, §4.1–4.6** | IETF | RFC | 5 min |
| 6 | [Understanding Authorization in MCP](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization.md) | Model Context Protocol | Tutorial | 10 min |

**Total: ~55 minutes**, of which item 2 is a skim. If you are short on time, read
items 1, 3, and 6 fully and skim 2.

### What to look for in each

**1 — OAuth 2.0 Simplified.** Read for the *roles* and the *authorization code
flow*. Skip the sections on client credentials and device flow; we do not use
them. When you finish, you should be able to say what a "public client" is and
why it cannot hold a secret.

**2 — OIDC Core §1–3.** §1 is terminology, §2 is the ID token, §3.1 is the
authorization-code flow with OIDC on top. **§2 is the important one.** Note which
claims are REQUIRED in an ID token.

**3 — OIDC Discovery §4, and the five-minute exercise.** §4 defines the
`/.well-known/openid-configuration` document. Then do this:

```bash
curl -s https://accounts.google.com/.well-known/openid-configuration
```

Find and write down these four values — you will be asked for them in class:

- `authorization_endpoint`
- `jwks_uri`
- `scopes_supported`
- `code_challenge_methods_supported`

Then fetch the JWKS that `jwks_uri` points at and **count the keys**:

```bash
curl -s https://www.googleapis.com/oauth2/v3/certs
```

Two things should surprise you. Bring both to class.

**4 — jwt.io.** Use only the debugger's built-in public example. Never paste
your own tenant token, local lab token, secret or cookie into an online decoder.
Look at the three
segments. **Then answer, honestly, for yourself:** did the page tell you the token
was *valid*, or only what it *contained*? That distinction is the title of Block B.

**5 — RFC 7636 §4.1–4.6.** Six short sections. They define `code_verifier`,
`code_challenge`, `S256`, and the check the authorization server performs. It is
about two pages and it is the whole mechanism.

**6 — Understanding Authorization in MCP.** Read the "Authorization Flow: Step by
Step" section carefully. You do not need to follow the Keycloak walkthrough — the
course tenant is already provisioned for you. Note where `401` appears, and what
the client is expected to do with it.

---

## Optional enrichment (not assigned, not on the readiness check)

- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) — the current, consolidated guidance. §2 is the short version.
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html) — what your MCP server must publish. Four pages.
- [MCP — Authorization, specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — the normative version of item 6.
- [OWASP — OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

---

## Come to class with

- [ ] The four discovery values and the JWKS key count from item 3, written down.
- [ ] The two things that surprised you.
- [ ] Your **Week 7 MCP server running**, or a note about why it isn't. The lab puts OAuth in front of it.
- [ ] Your client ID for the course tenant ([`README.md`](README.md)).

---

## Readiness check — 5 questions

Due before class in D2L. Auto-graded. The answer key is retained in the
instructor edition for feedback and debrief.

**Q1.** OAuth 2.0 was designed primarily to solve which problem?

- A. Proving who a user is to a website
- B. Letting one application act on a user's behalf at another, without the user's password
- C. Encrypting data in transit between a browser and a server
- D. Replacing session cookies with tokens

**Q2.** A client generates `code_verifier`, computes `code_challenge = BASE64URL(SHA256(code_verifier))`, and starts an authorization code flow. An attacker steals the authorization code from the browser's history. What does the attacker still need in order to obtain an access token?

- A. The `state` parameter
- B. The `code_challenge`
- C. The `code_verifier`
- D. The client secret

**Q3.** Your resource server receives a JWT access token. Its signature verifies against the issuer's JWKS, `iss` matches your configured issuer, and `exp` is 12 minutes in the future. Its `aud` claim names a **different** API in the same tenant. What should your server do?

- A. Accept it — the token is genuine and unexpired
- B. Accept it but log a warning
- C. Reject it with 403 Forbidden
- D. Reject it with 401 Unauthorized

**Q4.** What does pasting a JWT into jwt.io prove about that token?

- A. That its signature is valid
- B. That it has not expired
- C. That it was issued by the issuer named in `iss`
- D. Only what it contains — nothing about whether any of it is true

**Q5.** In the MCP authorization flow, an MCP client makes its first request to a protected MCP server with no access token. What must the server return, and what does the client do next?

- A. 403, and the client gives up
- B. 401 with a `WWW-Authenticate` header naming a `resource_metadata` URL; the client fetches that document to discover the authorization server
- C. 302 redirecting the client to the authorization server
- D. 200 with an empty result, since authorization in MCP is optional

---
---
