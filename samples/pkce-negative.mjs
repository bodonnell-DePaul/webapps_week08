/**
 * pkce-negative.mjs — prove PKCE and single-use codes actually do something.
 * CSC 436 Week 8. Run with the lab authorization server up.
 *
 *   node pkce-negative.mjs
 *
 * Produces four required HW7 artifacts in one run:
 *   1. token exchange with the WRONG code_verifier   -> 400 invalid_grant
 *   2. a failed exchange BURNS the code               -> 400 invalid_grant
 *   3. replay of an already-redeemed code             -> 400 invalid_grant
 *   4. an authorization request with no PKCE at all   -> 400 invalid_request
 *
 * (2) surprises people. THIS lab authorization server consumes the code on any
 * redemption attempt. RFC 7636 §4.6 requires only that a wrong verifier be
 * rejected; RFC 6749 §4.1.2 makes codes single-use and says the server SHOULD
 * revoke on detected reuse; RFC 9700 §2.1.1 pushes toward treating a failed
 * redemption as an attack signal. Real servers therefore differ. The reasoning
 * for the strict choice: if a wrong verifier arrived, somebody other than the
 * legitimate client is holding the code, and giving the real client a second
 * chance would give the attacker one too.
 *
 * TEST WHAT YOUR OWN PROVIDER DOES. That experiment is an HW7 line item.
 */

import { createHash, randomBytes } from 'node:crypto';

const AS = process.env.AS ?? 'http://127.0.0.1:9100';
const REDIRECT = 'http://127.0.0.1:5173/callback';
const RESOURCE = process.env.MCP_RESOURCE ?? 'http://127.0.0.1:8930/mcp';
const b = x => Buffer.from(x).toString('base64url');

/** Run one authorization request and return { verifier, challenge, code }. */
async function freshCode() {
    const verifier = b(randomBytes(32));
    const challenge = b(createHash('sha256').update(verifier).digest());
    const authorize = new URL(`${AS}/authorize`);
    authorize.search = new URLSearchParams({
        response_type: 'code',
        client_id: 'campuspulse-web',
        redirect_uri: REDIRECT,
        scope: 'openid campuspulse.read',
        state: `st_${b(randomBytes(6))}`,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        resource: RESOURCE,
    }).toString();
    const page = await (await fetch(authorize)).text();
    const link = /<a href="([^"]+)">Approve/.exec(page)[1].replace(/&amp;/g, '&');
    return { verifier, challenge, code: new URL(link).searchParams.get('code') };
}

const exchange = (code, v) => fetch(`${AS}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        client_id: 'campuspulse-web',
        code_verifier: v,
        resource: RESOURCE,
    }),
});

// --- A. a code that is attacked ---------------------------------------------
const A = await freshCode();
console.log(`\n[A] code_challenge  ${A.challenge}`);
console.log(`    code            ${A.code}`);

console.log('\n--- 1. exchange with the WRONG code_verifier -------------------');
const bad = await exchange(A.code, b(randomBytes(32)));
console.log(`HTTP ${bad.status}`);
console.log(JSON.stringify(await bad.json(), null, 2));
console.log('    ^ the stolen code is worthless without the verifier. That is PKCE.');

console.log('\n--- 2. the RIGHT verifier, on that same code -------------------');
const burned = await exchange(A.code, A.verifier);
console.log(`HTTP ${burned.status}`);
console.log(JSON.stringify(await burned.json(), null, 2));
console.log('    ^ THIS server consumed the code on the failed attempt.');
console.log('      RFC 7636 only requires rejecting the wrong verifier; RFC 9700');
console.log('      2.1.1 pushes toward revoking. Providers differ — test yours.');

// --- B. a clean code ---------------------------------------------------------
const B = await freshCode();
console.log('\n--- 3. a clean code, correct verifier, then replayed -----------');
const ok = await exchange(B.code, B.verifier);
const okBody = await ok.json();
console.log(`HTTP ${ok.status}  ${JSON.stringify({ token_type: okBody.token_type, expires_in: okBody.expires_in, scope: okBody.scope })}`);
const replay = await exchange(B.code, B.verifier);
console.log(`HTTP ${replay.status}  ${JSON.stringify(await replay.json())}`);
console.log('    ^ single use, always. RFC 6749 4.1.2: "MUST NOT be used more than once".');

// --- C. no PKCE at all -------------------------------------------------------
console.log('\n--- 4. an authorization request with no PKCE at all ------------');
const noPkce = await fetch(`${AS}/authorize?response_type=code&client_id=campuspulse-web&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=openid`);
const text = await noPkce.text();
const visible = (/<body>([\s\S]*)<\/body>/.exec(text)?.[1] ?? text)
    .replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
console.log(`HTTP ${noPkce.status}`);
console.log(`  ${visible.slice(0, 240)}`);
console.log('    ^ OAuth 2.1 makes PKCE mandatory for every client, not just public ones.\n');
