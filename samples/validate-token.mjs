/**
 * validate-token.mjs — decode a JWT, then actually validate it.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8. Zero dependencies: node:crypto only, Node >= 20.
 *
 *   node validate-token.mjs --token-file t.txt \
 *        --jwks http://127.0.0.1:9100/jwks.json \
 *        --issuer http://127.0.0.1:9100 \
 *        --audience http://127.0.0.1:8930/mcp \
 *        --scope campuspulse.read
 *
 *   node validate-token.mjs --variant expired          # pull one from the lab AS
 *   node validate-token.mjs --decode-only --variant id-token
 *
 * WHY IT IS WRITTEN BY HAND
 *
 * In production you use a maintained library — `jose`, `python-jose`,
 * `System.IdentityModel.Tokens.Jwt`, `github.com/lestrrat-go/jwx`. You are
 * writing it once, here, so that you have personally seen every check that
 * library performs, and so that when a token is rejected in Week 9 you can name
 * which check rejected it instead of guessing.
 *
 * The eight checks, in the order a resource server must run them:
 *
 *   1. structure     — three base64url segments
 *   2. alg           — an ALLOW-LIST from your config, never `header.alg`
 *   3. kid -> key    — resolve against the JWKS the issuer publishes
 *   4. signature     — cryptographic verification over `header.payload`
 *   5. iss           — exact string match against your configured issuer
 *   6. aud           — this token was minted FOR YOU
 *   7. exp / nbf     — with a bounded clock skew
 *   8. scope / roles — the authorization decision, which is not authentication
 *
 * Checks 1-7 are AUTHENTICATION: is this token real and is it mine.
 * Check 8 is AUTHORIZATION: may this subject do this particular thing.
 * They produce different HTTP status codes. 401 vs 403. That distinction is
 * graded.
 */

import { createHash, createPublicKey, createVerify, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

// ------------------------------------------------------------------ arguments

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = process.argv[i + 1];
    if (next && !next.startsWith('--')) { args.set(key, next); i++; } else { args.set(key, true); }
}

const AS = args.get('as') ?? 'http://127.0.0.1:9100';
const CONFIG = {
    jwksUri: args.get('jwks') ?? `${AS}/jwks.json`,
    issuer: args.get('issuer') ?? AS,
    audience: args.get('audience') ?? 'http://127.0.0.1:8930/mcp',
    requiredScope: args.get('scope') ?? null,
    // An ALLOW-LIST, not a preference (RFC 8725 §3.1). It is RS256-only because
    // that is the only algorithm this validator actually implements: the
    // verification call below is RSA-SHA256. Listing PS256 or ES256 here without
    // branching on them would be a real bug — the kind this course exists to
    // find — so the list and the implementation are kept in lockstep.
    // Your provider's supported algorithms are advertised in its metadata; use
    // the intersection of what it signs with and what your library implements.
    allowedAlgs: (args.get('algs') ?? 'RS256').split(','),
    clockSkewSeconds: Number(args.get('skew') ?? 60),
};

// ------------------------------------------------------------------- plumbing

const C = process.stdout.isTTY && !process.env.NO_COLOR
    ? { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, d: s => `\x1b[2m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` }
    : { g: s => s, r: s => s, d: s => s, b: s => s };
let failed = 0;
const results = [];
function check(name, ok, detail) {
    if (!ok) failed++;
    results.push({ name, ok, detail });
    console.log(`  ${ok ? C.g('PASS') : C.r('FAIL')}  ${name.padEnd(34)} ${detail ? C.d(detail) : ''}`);
}

/** The `error_description` a resource server should return for a failed check. */
const REASON = {
    'alg is on the allow-list': 'unacceptable signing algorithm',
    'kid resolves in JWKS': 'unknown signing key',
    'signature verifies': 'signature verification failed',
    'iss matches configured issuer': 'issuer mismatch',
    'aud contains this resource server': 'audience mismatch: this token was not issued for this resource',
    'exp is in the future': 'token expired',
    'nbf/iat are not in the future': 'token not yet valid',
    'JWKS fetched': 'could not retrieve issuer signing keys',
};

const decodeSeg = seg => JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));

async function getToken() {
    if (args.get('token-file')) return readFileSync(args.get('token-file'), 'utf8').trim();
    if (args.get('token')) return String(args.get('token')).trim();
    if (args.get('variant')) {
        const res = await fetch(`${AS}/mint?variant=${args.get('variant')}&raw`);
        if (!res.ok) throw new Error(`mint failed: ${res.status} ${await res.text()}`);
        return (await res.text()).trim();
    }
    // stdin
    const chunks = [];
    for await (const c of process.stdin) chunks.push(c);
    const s = Buffer.concat(chunks).toString('utf8').trim();
    if (!s) throw new Error('no token supplied (--token-file, --token, --variant, or stdin)');
    return s;
}

/** Print a token in a form that is safe to paste into a homework artifact. */
function redact(token) {
    const [h, p, s] = token.split('.');
    const clip = (x, n) => (x && x.length > n ? `${x.slice(0, n)}…<${x.length} chars>` : x);
    return `<header ${h?.length ?? 0} chars>\n.${clip(p, 20)}\n.${clip(s, 14)}`;
}

// ---------------------------------------------------------------------- main

const token = await getToken();

console.log(`\n${C.b('token, redacted for submission')}`);
console.log(redact(token).split('\n').map(l => `  ${l}`).join('\n'));

// -- 1. structure -----------------------------------------------------------
console.log(`\n${C.b('decode')}  ${C.d('— this proves nothing. Anyone can do it. Including an attacker.')}`);
const parts = token.split('.');
if (parts.length !== 3) {
    console.log(C.r(`  not a three-segment JWS: got ${parts.length} segment(s)`));
    process.exit(1);
}
let header, payload;
try {
    header = decodeSeg(parts[0]);
    payload = decodeSeg(parts[1]);
    if (!header || !payload || Array.isArray(header) || Array.isArray(payload) ||
        typeof header !== 'object' || typeof payload !== 'object') throw new Error('objects required');
} catch {
    console.error('REJECT 401 — malformed JWT header or payload');
    process.exit(1);
}
console.log(`  header  ${JSON.stringify(header)}`);
console.log(`  payload ${JSON.stringify(payload, null, 2).split('\n').join('\n          ')}`);

if (args.get('decode-only')) {
    console.log(`\n${C.d('--decode-only: stopping before validation. This is the mistake.')}\n`);
    process.exitCode = 0;
} else {
await validate();
}

async function validate() {
// -- validation -------------------------------------------------------------
console.log(`\n${C.b('validate')}  ${C.d(`against ${CONFIG.jwksUri}`)}`);

// 2. algorithm allow-list. Never trust header.alg to select the algorithm.
check(
    'alg is on the allow-list',
    CONFIG.allowedAlgs.includes(header.alg),
    `header.alg=${header.alg}; allowed=${CONFIG.allowedAlgs.join('|')}`,
);
if (header.alg === 'none') {
    console.log(C.r('        ^ `alg: none` is unsigned. CVE-2015-9235 is a different RS256/HS256 confusion bug.'));
}

// 3. resolve kid against the published JWKS
let jwks = { keys: [] };
try {
    const res = await fetch(CONFIG.jwksUri);
    jwks = await res.json();
} catch (e) {
    check('JWKS fetched', false, e.message);
}
const jwk = jwks.keys?.find(k => k.kid === header.kid) ?? null;
check(
    'kid resolves in JWKS',
    Boolean(jwk),
    jwk ? `kid=${header.kid}` : `kid=${header.kid ?? '(absent)'} not among [${(jwks.keys ?? []).map(k => k.kid).join(', ')}]`,
);

// 4. signature
let sigOk = false;
if (jwk && CONFIG.allowedAlgs.includes(header.alg) && header.alg === 'RS256') {
    try {
        const key = createPublicKey({ key: jwk, format: 'jwk' });
        const verifier = createVerify('RSA-SHA256');
        verifier.update(`${parts[0]}.${parts[1]}`);
        sigOk = verifier.verify(key, Buffer.from(parts[2], 'base64url'));
    } catch (e) {
        sigOk = false;
    }
}
check('signature verifies', sigOk, sigOk ? 'RS256 over header.payload' : 'cryptographic verification failed');

// 5. issuer — exact string comparison, no normalisation
check(
    'iss matches configured issuer',
    payload.iss === CONFIG.issuer,
    `token iss=${payload.iss}  expected=${CONFIG.issuer}`,
);

// 6. audience — the check people skip
const auds = Array.isArray(payload.aud) ? payload.aud : payload.aud === undefined ? [] : [payload.aud];
check(
    'aud contains this resource server',
    auds.includes(CONFIG.audience),
    `token aud=${JSON.stringify(payload.aud)}  expected to contain=${CONFIG.audience}`,
);

// The ID-token-as-API-token mistake, named explicitly.
if (header.typ === 'JWT' && payload.nonce !== undefined && !auds.includes(CONFIG.audience)) {
    console.log(C.r('        ^ this looks like an ID TOKEN. Its audience is the client, not the API.'));
}

// 7. temporal validity, with bounded skew
const nowSec = Math.floor(Date.now() / 1000);
const skew = CONFIG.clockSkewSeconds;
check(
    'exp is in the future',
    typeof payload.exp === 'number' && payload.exp + skew > nowSec,
    typeof payload.exp === 'number'
        ? `exp=${payload.exp} (${new Date(payload.exp * 1000).toISOString()}), now=${nowSec}, delta=${payload.exp - nowSec}s, skew=${skew}s`
        : 'exp absent',
);
check(
    'nbf/iat are not in the future',
    (payload.nbf === undefined || payload.nbf - skew <= nowSec) && (payload.iat === undefined || payload.iat - skew <= nowSec),
    `nbf=${payload.nbf ?? '-'} iat=${payload.iat ?? '-'} now=${nowSec} skew=${skew}s`,
);

// 8. authorization — a different question, and a different status code
// OAuth `scope` is a SPACE-delimited string (RFC 6749 §3.3). Some providers use
// a `scp` array instead; handle both, and nothing else.
const granted = Array.isArray(payload.scp)
    ? payload.scp
    : String(payload.scope ?? payload.scp ?? '').split(' ').filter(Boolean);
if (CONFIG.requiredScope) {
    check(
        `scope includes ${CONFIG.requiredScope}`,
        granted.includes(CONFIG.requiredScope),
        `granted=[${granted.join(' ')}]`,
    );
}

// ------------------------------------------------------------------- verdict

const authnChecks = results.slice(0, CONFIG.requiredScope ? -1 : results.length);
const authnFailed = authnChecks.some(r => !r.ok);
const authzFailed = CONFIG.requiredScope ? !results[results.length - 1].ok : false;

console.log('');
if (authnFailed) {
    const first = authnChecks.find(r => !r.ok);
    console.log(`${C.r('REJECT 401')}  ${C.d('the token is not usable: ' + authnChecks.filter(r => !r.ok).map(r => r.name).join('; '))}`);
    console.log(`            WWW-Authenticate: Bearer error="invalid_token", error_description="${REASON[first.name] ?? first.name}"`);
} else if (authzFailed) {
    console.log(`${C.r('REJECT 403')}  ${C.d('the token is genuine and yours, but this subject may not do this')}`);
    console.log(`            WWW-Authenticate: Bearer error="insufficient_scope", scope="${CONFIG.requiredScope}"`);
} else {
    console.log(`${C.g('ACCEPT 200')}  sub=${payload.sub} scope=[${granted.join(' ')}] roles=${JSON.stringify(payload.roles ?? [])}`);
}
console.log('');
process.exitCode = failed === 0 ? 0 : 1;
}
