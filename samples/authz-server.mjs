/**
 * authz-server.mjs — a deliberately small, deliberately honest OIDC-shaped
 * authorization server, for CSC 436 Week 8.
 * ---------------------------------------------------------------------------
 *   node authz-server.mjs            # listens on http://127.0.0.1:9100
 *   PORT=9100 node authz-server.mjs
 *
 * WHY THIS EXISTS
 *
 * The course tenant (Keycloak or Entra External ID) is the *real* identity
 * provider and you use it for the redirect walk in Lab Part 1. But a lab needs
 * three things a real tenant will never give you:
 *
 *   1. a token that is ALREADY EXPIRED, on demand;
 *   2. a token with a DELIBERATELY WRONG audience or issuer;
 *   3. a guarantee that nothing you paste into a terminal is a live credential.
 *
 * So Parts 2-5 run against this. Every token it mints is a *real* RS256 JWT
 * with a *real* signature over a *real* key — the key is generated fresh in
 * memory at startup and is thrown away when you press Ctrl+C. Tokens and codes
 * are usable against this local environment while it runs; redact them too.
 *
 * NOT PRODUCTION. There is no user database, no consent screen, no rate
 * limiting, no client authentication, and the "login" is a query parameter.
 * It implements exactly enough of RFC 6749 / RFC 7636 / OIDC Discovery to make
 * the failure modes visible.
 *
 * ZERO DEPENDENCIES. node:crypto and node:http only, Node >= 20.
 *
 * Endpoints
 *   GET  /.well-known/openid-configuration   OIDC discovery document
 *   GET  /jwks.json                          JWKS (public keys only)
 *   GET  /authorize                          auth code + PKCE; redirects
 *   POST /token                              code -> tokens (verifies PKCE)
 *   POST /introspect                         token activity check (lab JWTs only)
 *   GET  /mint?variant=...                   LAB SHORTCUT: skip the browser
 *   GET  /rotate                             rotate the signing key (adds a kid)
 */

import { createServer } from 'node:http';
import { createHash, createSign, createVerify, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 9100);
const HOST = process.env.AS_HOST ?? '127.0.0.1';
if (HOST !== '127.0.0.1') throw new Error('The demonstration issuer must stay on 127.0.0.1.');
const ISSUER = process.env.AS_ISSUER ?? `http://${HOST}:${PORT}`;

/** The audience of the MCP resource server this AS issues tokens for. */
const MCP_RESOURCE = process.env.MCP_RESOURCE ?? 'http://127.0.0.1:8930/mcp';
const WEB_CLIENT_ID = 'campuspulse-web';
const MCP_CLIENT_ID = 'campuspulse-mcp-client';

const SCOPES = [
    'openid',
    'profile',
    'email',
    'offline_access',
    'campuspulse.read',
    'campuspulse.incident.write',
];

// ------------------------------------------------------------------- helpers

const b64url = buf => Buffer.from(buf).toString('base64url');
const json = obj => JSON.stringify(obj);
const now = () => Math.floor(Date.now() / 1000);

// --------------------------------------------------------------- signing keys

/** kid -> { publicKey, privateKey }. `rotate` pushes a new one on the front. */
const keys = [];

function newKey() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    // A kid that is a thumbprint of the key, the way real providers do it
    // (RFC 7638 JWK thumbprint: lexicographic, no whitespace).
    const kid = b64url(
        createHash('sha256')
            .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }))
            .digest(),
    );
    const entry = { kid, publicKey, privateKey, jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' } };
    keys.unshift(entry);
    return entry;
}

newKey();

const activeKey = () => keys[0];

// -------------------------------------------------------------- token minting

function sign(header, payload, key = activeKey()) {
    const h = b64url(json({ ...header, kid: key.kid }));
    const p = b64url(json(payload));
    const signer = createSign('RSA-SHA256');
    signer.update(`${h}.${p}`);
    return `${h}.${p}.${signer.sign(key.privateKey, 'base64url')}`;
}

/**
 * The claim sets this course teaches. Every variant below is a REAL signed
 * token; what varies is whether the claims are ones a correct resource server
 * should accept.
 */
function accessToken(overrides = {}, opts = {}) {
    const iat = overrides.iat ?? now();
    const payload = {
        iss: ISSUER,
        sub: 'a4f1c0de-7c1b-4a2e-9f10-3d5c0b8e2a11',
        aud: MCP_RESOURCE,
        // RFC 9068 §2.2 names `client_id` for an `at+jwt` access token. Many
        // real providers (Keycloak among them) also or instead emit `azp`,
        // which OIDC defines for ID tokens. Both are here so you can see the
        // difference and check which one YOUR provider actually sends.
        client_id: WEB_CLIENT_ID,
        azp: WEB_CLIENT_ID,
        exp: iat + 900,
        iat,
        nbf: iat,
        jti: randomUUID(),
        typ: 'Bearer',
        scope: 'openid campuspulse.read',
        roles: ['viewer'],
        amr: ['pwd'],
        'campuspulse/campus': 'Riverbend',
        ...overrides,
    };
    return sign({ alg: 'RS256', typ: 'at+jwt' }, payload, opts.key);
}

function idToken(overrides = {}) {
    const iat = now();
    const payload = {
        iss: ISSUER,
        sub: 'a4f1c0de-7c1b-4a2e-9f10-3d5c0b8e2a11',
        aud: WEB_CLIENT_ID, // <- the CLIENT, not the API. This is the whole lesson.
        exp: iat + 900,
        iat,
        auth_time: iat - 42,
        amr: ['pwd'],
        name: 'Dana Okonkwo',
        email: 'dana.okonkwo@campuspulse.example',
        email_verified: true,
        ...overrides,
    };
    // `nonce` is REQUIRED in the ID token only when the client sent one.
    // Emitting it unconditionally would teach the wrong thing.
    if (payload.nonce === undefined) delete payload.nonce;
    return sign({ alg: 'RS256', typ: 'JWT' }, payload);
}

/**
 * The variants the lab uses. Each one exists to make exactly one validation
 * check fail, so a student can see which check caught it.
 */
const VARIANTS = {
    valid: () => ({ note: 'everything correct; viewer scope', token: accessToken() }),
    operator: () => ({
        note: 'read + write scope, operator role',
        token: accessToken({ scope: 'openid campuspulse.read campuspulse.incident.write', roles: ['operator'] }),
    }),
    'viewer-write': () => ({
        note: 'write scope but viewer role; a separate role check must deny',
        token: accessToken({ scope: 'campuspulse.read campuspulse.incident.write', roles: ['viewer'] }),
    }),
    'operator-read': () => ({
        note: 'operator role but read-only client scope; scope check must deny',
        token: accessToken({ scope: 'campuspulse.read', roles: ['operator'] }),
    }),
    expired: () => ({
        note: 'signature is valid; exp is 40 minutes in the past',
        token: accessToken({ iat: now() - 3300 }), // exp = iat + 900 => 40 min ago
    }),
    'wrong-issuer': () => ({
        note: 'signed by THIS server but claiming a different iss',
        token: accessToken({ iss: 'https://login.evil-campus.example/realms/campuspulse' }),
    }),
    'wrong-audience': () => ({
        note: 'a perfectly valid token — for a different API',
        token: accessToken({ aud: 'https://grades.campuspulse.example/api' }),
    }),
    'not-yet-valid': () => ({
        note: 'nbf is 10 minutes in the future — the clock-skew case',
        token: accessToken({ nbf: now() + 600 }),
    }),
    'no-scope': () => ({
        note: 'authenticated, but carries no campuspulse scope at all',
        token: accessToken({ scope: 'openid profile email' }),
    }),
    'id-token': () => ({
        note: 'an ID TOKEN. aud is the client. Never send this to an API.',
        token: idToken({ nonce: 'n-0S6_WzA2Mj' }),
    }),
    'stale-kid': () => ({
        note: 'signed by a retired key; kid is not in the current JWKS',
        token: (() => {
            const throwaway = (() => {
                const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
                return { kid: 'retired-2025-key', publicKey, privateKey };
            })();
            return accessToken({}, { key: throwaway });
        })(),
    }),
};

// -------------------------------------------------------- authorization codes

/** code -> { code_challenge, method, scope, resource, nonce, state, exp } */
const codes = new Map();

/**
 * Refresh tokens, with rotation and reuse detection.
 *   token -> { family, scope, resource, role, clientId, used }
 * Presenting a token that has already been rotated is evidence of theft: the
 * honest client and the thief both eventually hold a copy. On reuse we revoke
 * the ENTIRE family, which turns silent persistent access into a detected
 * incident. This is the mechanism Block C describes.
 */
const refreshTokens = new Map();

function issueRefreshToken(family, meta) {
    const t = `rt_${randomBytes(24).toString('hex')}`;
    refreshTokens.set(t, { family, used: false, ...meta });
    return t;
}

function revokeFamily(family) {
    let n = 0;
    for (const [t, v] of refreshTokens) {
        if (v.family === family) { refreshTokens.delete(t); n++; }
    }
    return n;
}

function html(body) {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>CSC 436 lab authorization server</title>
<style>body{font:16px/1.5 system-ui,sans-serif;background:#0B1B2B;color:#F3F8FC;padding:2rem;max-width:52rem;margin:auto}
code,pre{font-family:Cascadia Code,Consolas,monospace;background:#17364E;padding:.15rem .35rem;border-radius:4px}
pre{padding:1rem;overflow:auto}a{color:#93C5FD}h1{color:#5EEAD4}.warn{color:#FCD34D}</style></head>
<body>${body}</body></html>`;
}

// ---------------------------------------------------------------- the server

const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const send = (status, obj, type = 'application/json') => {
        const body = type === 'application/json' ? json(obj) : obj;
        res.writeHead(status, {
            'content-type': `${type}; charset=utf-8`,
            'cache-control': 'no-store',
            'access-control-allow-origin': '*',
        });
        res.end(body);
    };

    // ---- OIDC discovery -----------------------------------------------------
    if (url.pathname === '/.well-known/openid-configuration' || url.pathname === '/.well-known/oauth-authorization-server') {
        return send(200, {
            issuer: ISSUER,
            authorization_endpoint: `${ISSUER}/authorize`,
            token_endpoint: `${ISSUER}/token`,
            introspection_endpoint: `${ISSUER}/introspect`,
            jwks_uri: `${ISSUER}/jwks.json`,
            end_session_endpoint: `${ISSUER}/logout`,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'refresh_token'],
            code_challenge_methods_supported: ['S256'],
            id_token_signing_alg_values_supported: ['RS256'],
            token_endpoint_auth_methods_supported: ['none'],
            scopes_supported: SCOPES,
            claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'azp', 'scope', 'roles', 'amr', 'nonce', 'email'],
            authorization_response_iss_parameter_supported: true,
            subject_types_supported: ['public'],
        });
    }

    // ---- JWKS ---------------------------------------------------------------
    if (url.pathname === '/jwks.json') {
        return send(200, { keys: keys.map(k => k.jwk) });
    }

    // ---- key rotation, for the "cache your JWKS but not forever" demo -------
    if (url.pathname === '/rotate') {
        const k = newKey();
        return send(200, { rotated: true, activeKid: k.kid, kidsInJwks: keys.map(x => x.kid) });
    }

    // ---- authorization endpoint --------------------------------------------
    if (url.pathname === '/authorize') {
        const q = url.searchParams;
        const missing = ['client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method']
            .filter(k => !q.get(k));

        // PKCE is not optional here. This is the teaching point.
        if (missing.length) {
            return send(
                400,
                html(`<h1>invalid_request</h1><p>Missing: <code>${missing.join('</code>, <code>')}</code></p>
<p class="warn">This lab authorization server refuses an authorization request without PKCE,
the way OAuth 2.1 requires. Add <code>code_challenge</code> and
<code>code_challenge_method=S256</code>.</p>`),
                'text/html',
            );
        }
        if (q.get('response_type') !== 'code') {
            return send(400, html('<h1>unsupported_response_type</h1><p>Only <code>code</code>. The implicit flow is gone.</p>'), 'text/html');
        }
        if (q.get('code_challenge_method') !== 'S256') {
            return send(400, html('<h1>invalid_request</h1><p><code>plain</code> is not accepted. Use <code>S256</code>.</p>'), 'text/html');
        }

        const code = `lab_${randomBytes(24).toString('hex')}`;
        codes.set(code, {
            challenge: q.get('code_challenge'),
            scope: q.get('scope') ?? 'openid campuspulse.read',
            resource: q.get('resource') ?? MCP_RESOURCE,
            nonce: q.get('nonce'),
            clientId: q.get('client_id'),
            redirectUri: q.get('redirect_uri'),
            role: q.get('login_as') === 'operator' ? 'operator' : 'viewer',
            exp: now() + 60,
        });

        const back = new URL(q.get('redirect_uri'));
        back.searchParams.set('code', code);
        if (q.get('state')) back.searchParams.set('state', q.get('state'));
        back.searchParams.set('iss', ISSUER); // RFC 9207

        // A "consent screen" you can read in one glance.
        return send(
            200,
            html(`<h1>Authorize CampusPulse</h1>
<p><strong>${q.get('client_id')}</strong> is asking for:</p>
<pre>${(q.get('scope') ?? '').split(' ').join('\n')}</pre>
<p>Resource (RFC 8707): <code>${q.get('resource') ?? '(none sent)'}</code></p>
<p>Signed in as: <code>${q.get('login_as') === 'operator' ? 'operator' : 'viewer'}</code>
(append <code>&amp;login_as=operator</code> to change)</p>
<p><a href="${back}">Approve and return to the client &rarr;</a></p>
<p class="warn">Look at that link before you click it. The authorization code is
about to travel in a URL, through your browser's history, and into a Referer
header if the callback page loads anything cross-origin. That is why the code is
useless without the <code>code_verifier</code>.</p>`),
            'text/html',
        );
    }

    // ---- token endpoint -----------------------------------------------------
    if (url.pathname === '/token' && req.method === 'POST') {
        const body = await readBody(req);
        const form = new URLSearchParams(body);
        const grant = form.get('grant_type');

        if (grant === 'refresh_token') {
            const presented = form.get('refresh_token') ?? '';
            const entry = refreshTokens.get(presented);
            if (!entry) {
                return send(400, { error: 'invalid_grant', error_description: 'unknown or already-rotated refresh token' });
            }
            if (form.get('client_id') !== entry.clientId) {
                return send(400, { error: 'invalid_grant', error_description: 'refresh token belongs to a different client' });
            }
            if (entry.used) {
                // Reuse detection. The honest client and a thief both hold a
                // copy of this token; we cannot tell which one just presented
                // it, so we revoke the whole family and make both re-authorize.
                const revoked = revokeFamily(entry.family);
                return send(400, {
                    error: 'invalid_grant',
                    error_description: `refresh token reuse detected; revoked ${revoked} token(s) in this family`,
                });
            }
            // Mark rotated but KEEP the entry as a tombstone. Deleting it here
            // would make a later reuse look like "unknown token" and the
            // detection would silently never fire — which is exactly the class
            // of bug this course exists to find.
            entry.used = true;
            const next = issueRefreshToken(entry.family, {
                scope: entry.scope, resource: entry.resource, role: entry.role, clientId: entry.clientId,
            });
            return send(200, {
                access_token: accessToken({
                    aud: entry.resource,
                    azp: entry.clientId,
                    client_id: entry.clientId,
                    scope: entry.scope,
                    roles: [entry.role],
                }),
                token_type: 'Bearer',
                expires_in: 900,
                refresh_token: next,
                scope: entry.scope,
            });
        }

        if (grant !== 'authorization_code') {
            return send(400, { error: 'unsupported_grant_type' });
        }

        const code = form.get('code');
        const entry = codes.get(code);
        if (!entry) return send(400, { error: 'invalid_grant', error_description: 'unknown or already-redeemed code' });
        codes.delete(code); // this server consumes a code on ANY redemption attempt
        if (entry.exp <= now()) return send(400, { error: 'invalid_grant', error_description: 'code expired' });

        // RFC 6749 §4.1.3: the client_id and redirect_uri presented at the token
        // endpoint MUST match the ones used at the authorization endpoint.
        if (form.get('client_id') !== entry.clientId) {
            return send(400, { error: 'invalid_grant', error_description: 'client_id does not match the authorization request' });
        }
        if (form.get('redirect_uri') !== entry.redirectUri) {
            return send(400, { error: 'invalid_grant', error_description: 'redirect_uri does not match the authorization request' });
        }

        const verifier = form.get('code_verifier');
        if (!verifier) {
            return send(400, { error: 'invalid_request', error_description: 'code_verifier required' });
        }
        const computed = b64url(createHash('sha256').update(verifier).digest());
        if (computed !== entry.challenge) {
            return send(400, {
                error: 'invalid_grant',
                error_description: 'PKCE verification failed: S256(code_verifier) != code_challenge',
                expected_challenge: entry.challenge,
                computed_challenge: computed,
            });
        }

        const scope = entry.scope;
        const isOperator = entry.role === 'operator';
        const grantedScope = isOperator
            ? scope
            : scope.replace(/\bcampuspulse\.incident\.write\b/, '').replace(/\s+/g, ' ').trim();

        const out = {
            access_token: accessToken({
                aud: entry.resource,
                azp: entry.clientId,
                client_id: entry.clientId,
                scope: grantedScope,
                roles: [entry.role],
            }),
            token_type: 'Bearer',
            expires_in: 900,
            scope: grantedScope,
        };
        if (scope.split(' ').includes('openid')) {
            out.id_token = idToken({
                aud: entry.clientId,
                ...(entry.nonce ? { nonce: entry.nonce } : {}),
            });
        }
        if (scope.split(' ').includes('offline_access')) {
            out.refresh_token = issueRefreshToken(randomUUID(), {
                scope: grantedScope, resource: entry.resource, role: entry.role, clientId: entry.clientId,
            });
        }
        return send(200, out);
    }

    // ---- introspection (RFC 7662) ------------------------------------------
    // NOTE: a production introspection endpoint MUST authenticate its caller
    // (RFC 7662 §2.1) — otherwise it is an oracle that tells anyone whether a
    // stolen token is live. This one does not, because there is no client
    // registry in a lab. It DOES verify the signature, because an introspection
    // endpoint that merely decodes would report a forged token as active, which
    // is the exact mistake Block B exists to prevent.
    if (url.pathname === '/introspect' && req.method === 'POST') {
        const form = new URLSearchParams(await readBody(req));
        const token = form.get('token') ?? '';
        const parts = token.split('.');
        if (parts.length !== 3) return send(200, { active: false });
        try {
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
            const key = keys.find(k => k.kid === header.kid);
            if (!key || header.alg !== 'RS256') return send(200, { active: false });
            const v = createVerify('RSA-SHA256');
            v.update(`${parts[0]}.${parts[1]}`);
            if (!v.verify(key.publicKey, Buffer.from(parts[2], 'base64url'))) {
                return send(200, { active: false });
            }
            const active = payload.exp > now() && payload.iss === ISSUER &&
                (payload.nbf === undefined || payload.nbf <= now());
            return send(200, active ? { active: true, ...payload } : { active: false });
        } catch {
            return send(200, { active: false });
        }
    }

    // ---- lab shortcut: mint a variant without a browser --------------------
    if (url.pathname === '/mint') {
        const name = url.searchParams.get('variant') ?? 'valid';
        const ttl = url.searchParams.get('ttl');
        if (ttl) {
            // Short-lived token, for the "expires mid-connection" demo.
            const iat = now();
            const token = accessToken({
                iat,
                exp: iat + Number(ttl),
                scope: 'openid campuspulse.read',
            });
            return send(200, { variant: `valid+ttl=${ttl}s`, note: `expires in ${ttl}s`, token });
        }
        const make = VARIANTS[name];
        if (!make) {
            return send(404, { error: 'unknown_variant', known: Object.keys(VARIANTS) });
        }
        const { note, token } = make();
        if (url.searchParams.get('raw') !== null) {
            return send(200, token, 'text/plain');
        }
        return send(200, { variant: name, note, token });
    }

    if (url.pathname === '/logout') {
        return send(200, html('<h1>Demonstration only</h1><p>This issuer has no login session to destroy. This page does not revoke access or refresh tokens. Test actual logout and session invalidation with your provisioned identity provider.</p>'), 'text/html');
    }

    if (url.pathname === '/') {
        return send(
            200,
            html(`<h1>CSC 436 lab authorization server</h1>
<p>Issuer: <code>${ISSUER}</code></p>
<ul>
<li><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></li>
<li><a href="/jwks.json">/jwks.json</a></li>
<li><a href="/mint?variant=valid">/mint?variant=…</a> — ${Object.keys(VARIANTS).join(', ')}</li>
</ul>
<p class="warn">Not production. Keys are generated in memory at startup and die with the process.</p>`),
            'text/html',
        );
    }

    send(404, { error: 'not_found' });
});

function readBody(req) {
    return new Promise(resolve => {
        let data = '';
        req.on('data', c => (data += c));
        req.on('end', () => resolve(data));
    });
}

server.listen(PORT, HOST, () => {
    console.log(
        [
            '',
            '  CSC 436 Week 8 — lab authorization server',
            `  issuer     : ${ISSUER}`,
            `  discovery  : ${ISSUER}/.well-known/openid-configuration`,
            `  jwks       : ${ISSUER}/jwks.json`,
            `  active kid : ${activeKey().kid}`,
            `  audience   : ${MCP_RESOURCE}`,
            '',
            '  Keys die on exit. Tokens/codes work locally while running: redact them.',
            '',
        ].join('\n'),
    );
});
