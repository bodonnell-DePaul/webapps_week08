/**
 * pkce.mjs — build a PKCE pair and the authorization URL that uses it.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, Lab Part 1. Zero dependencies.
 *
 *   node pkce.mjs                                   # against the lab AS
 *   node pkce.mjs --discovery https://<tenant>/.well-known/openid-configuration \
 *                 --client-id <your-client-id> \
 *                 --redirect-uri http://127.0.0.1:5173/callback \
 *                 --scope "openid campuspulse.read" \
 *                 --resource https://mcp.<yourdomain>/mcp
 *
 * WHAT PKCE ACTUALLY DOES, IN ONE PARAGRAPH
 *
 * The authorization code travels back through the browser: in a URL, into
 * history, into the address bar, sometimes into a Referer header, sometimes
 * into a native app's custom-scheme handler that another app also registered.
 * Assume it leaks. PKCE makes the leak worthless: the client invents a secret
 * (`code_verifier`), sends only its SHA-256 hash up front (`code_challenge`),
 * and must present the original at the token endpoint. Whoever stole the code
 * did not see the verifier, so the code will not exchange.
 *
 * `state` is a different control for a different attack: it binds the callback
 * to the browser session that started it, which is CSRF defence. PKCE does not
 * replace it. `nonce` is a third control: it binds the ID TOKEN to this
 * authentication attempt, and it is checked by the client, not the API.
 *
 * See RFC 7636 §4.1-4.6 and RFC 9700 §2.1.1.
 */

import { createHash, randomBytes } from 'node:crypto';

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (!a.startsWith('--')) continue;
    const next = process.argv[i + 1];
    if (next && !next.startsWith('--')) { args.set(a.slice(2), next); i++; } else { args.set(a.slice(2), true); }
}

const b64url = b => Buffer.from(b).toString('base64url');

// RFC 7636 §4.1: 43-128 characters from the unreserved set. 32 random bytes
// base64url-encoded gives 43 characters and 256 bits of entropy. Do not use
// Math.random(); do not use a timestamp; do not reuse one across requests.
const codeVerifier = b64url(randomBytes(32));
const codeChallenge = b64url(createHash('sha256').update(codeVerifier).digest());
const state = b64url(randomBytes(16));
const nonce = b64url(randomBytes(16));

const discoveryUrl = args.get('discovery') ?? 'http://127.0.0.1:9100/.well-known/openid-configuration';
const res = await fetch(discoveryUrl);
if (!res.ok) {
    console.error(`discovery fetch failed: ${res.status} ${discoveryUrl}`);
    process.exitCode = 1;
} else {
    const meta = await res.json();

    const authorizeUrl = new URL(meta.authorization_endpoint);
    const p = authorizeUrl.searchParams;
    p.set('response_type', 'code');
    p.set('client_id', String(args.get('client-id') ?? 'campuspulse-web'));
    p.set('redirect_uri', String(args.get('redirect-uri') ?? 'http://127.0.0.1:5173/callback'));
    p.set('scope', String(args.get('scope') ?? 'openid campuspulse.read'));
    p.set('state', state);
    p.set('nonce', nonce);
    p.set('code_challenge', codeChallenge);
    p.set('code_challenge_method', 'S256');
    // RFC 8707. MCP clients MUST send this in BOTH the authorization request
    // and the token request. It is what makes `aud` on the resulting token
    // mean something.
    p.set('resource', String(args.get('resource') ?? 'http://127.0.0.1:8930/mcp'));

    console.log(`
provider          ${meta.issuer}
authorize         ${meta.authorization_endpoint}
token             ${meta.token_endpoint}
jwks              ${meta.jwks_uri}
pkce methods      ${(meta.code_challenge_methods_supported ?? ['(not advertised)']).join(', ')}
iss in response   ${meta.authorization_response_iss_parameter_supported === true ? 'yes (RFC 9207)' : 'not advertised'}

code_verifier     ${codeVerifier}
                  ^ Goes ONLY to the token endpoint, over TLS, direct from your
                    client. Never in a redirect URL, never in a log, never in
                    anything a browser or a third party can read.
code_challenge    ${codeChallenge}
                  ^ = BASE64URL(SHA256(code_verifier)), sent in the clear
state             ${state}
nonce             ${nonce}

authorization URL for inspection (this helper starts NO callback server):

${authorizeUrl}

For a complete browser sign-in, from the course-content root after the
documented installs: npm --prefix samples/oidc-web-app run demo
That separate application supplies its own provider and working callback.

Optional public-client manual exchange template (Bash, not PowerShell).
Use only with a callback you operate; replace PASTE_CALLBACK_CODE:

curl -s -X POST ${meta.token_endpoint} \\
  -d grant_type=authorization_code \\
  --data-urlencode "code=PASTE_CALLBACK_CODE" \\
  -d redirect_uri=${encodeURIComponent(String(args.get('redirect-uri') ?? 'http://127.0.0.1:5173/callback'))} \\
  -d client_id=${encodeURIComponent(String(args.get('client-id') ?? 'campuspulse-web'))} \\
  -d code_verifier=${codeVerifier} \\
  -d resource=${encodeURIComponent(String(args.get('resource') ?? 'http://127.0.0.1:8930/mcp'))}

Now do it a second time with a WRONG code_verifier and read the error body.
That error is the entire value of PKCE, and it is a required HW7 artifact.
`);
}
