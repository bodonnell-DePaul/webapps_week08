/**
 * mcp-auth-proxy.mjs — put OAuth in front of last week's MCP server.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, Lab Part 5. Zero dependencies: node:crypto + node:http.
 *
 *   node mcp-auth-proxy.mjs                       # 8930 -> 8931
 *   MCP_UPSTREAM=stub node mcp-auth-proxy.mjs     # no Week 7 server needed
 *
 * WHAT IT IMPLEMENTS, AND WHERE THE SPEC SAYS SO
 *
 *   RFC 9728  Protected Resource Metadata at
 *             /.well-known/oauth-protected-resource
 *             MCP spec 2026-07-28 §Overview(4): "MCP servers MUST implement
 *             OAuth 2.0 Protected Resource Metadata".
 *
 *   RFC 6750  401 + WWW-Authenticate: Bearer ... on a missing/invalid token;
 *             403 + error="insufficient_scope" when the token is genuine but
 *             does not carry the scope this operation needs.
 *
 *   RFC 8707  Audience binding. `aud` must name THIS resource server. A token
 *             minted for the grades API is a valid token and is still rejected.
 *
 * THE INTERESTING PART — PER-TOOL SCOPE, WITHOUT PARSING THE BODY
 *
 * Spec revision 2026-07-28 requires every request that names a target to name
 * it in a header as well: `Mcp-Method: tools/call` and
 * `Mcp-Name: post_incident_update`. That exists precisely so an intermediary
 * like this one can make an authorization decision without parsing JSON-RPC,
 * and so the proxy cannot be shown one target while the server executes
 * another. We still cross-check header against body, because "the spec says
 * they agree" is a design assumption, not a control.
 *
 * NOT PRODUCTION. No TLS, no rate limiting, no key-cache TTL tuning, no
 * introspection fallback, single upstream. It is the smallest thing that makes
 * every failure mode visible in a 35-minute lab.
 */

import { createServer, request as httpRequest } from 'node:http';
import { createPublicKey, createVerify } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 8930);
const HOST = process.env.PROXY_HOST ?? '127.0.0.1';
if (HOST !== '127.0.0.1') throw new Error('The teaching proxy must stay on 127.0.0.1.');
const RESOURCE = process.env.MCP_RESOURCE ?? `http://${HOST}:${PORT}/mcp`;
const AS_ISSUER = process.env.AS_ISSUER ?? 'http://127.0.0.1:9100';
const JWKS_URI = process.env.JWKS_URI ?? `${AS_ISSUER}/jwks.json`;
const UPSTREAM = process.env.MCP_UPSTREAM ?? 'http://127.0.0.1:8931/mcp';
const SKEW = Number(process.env.CLOCK_SKEW ?? 60);
const PRM_PATH = '/.well-known/oauth-protected-resource';

/**
 * Stream supervision. `subscriptions/listen` is a single long-lived POST
 * stream in spec revision 2026-07-28 — one authorization decision, then
 * minutes or hours of data. That is the Week 7 / Week 8 collision: the token
 * that opened the stream expires while the stream is still open.
 *
 * ENFORCE_STREAM_EXPIRY=0  reproduce the bug: the stream outlives the token
 * ENFORCE_STREAM_EXPIRY=1  the fix: the proxy cuts the stream at `exp`
 */
const ENFORCE_STREAM_EXPIRY = process.env.ENFORCE_STREAM_EXPIRY !== '0';

/**
 * The authorization policy. One line per capability.
 *
 * This is the artifact HW7 asks you to submit, and it is the part a model
 * cannot write for you: it encodes which of YOUR tools change state and which
 * only read. Get a row wrong here and a viewer can post an incident update.
 *
 * Two independent gates, because scope and role answer different questions:
 *   TOOL_SCOPES  what the CLIENT was granted permission to do (consent)
 *   TOOL_ROLES   what the USER is allowed to do (administration)
 * The effective permission is the intersection. A read-only client used by an
 * operator still cannot write; a full-scope client used by a viewer cannot
 * either.
 */
const TOOL_SCOPES = {
    'list_service_status': 'campuspulse.read',
    'get_incident': 'campuspulse.read',
    'post_incident_update': 'campuspulse.incident.write',
    'draft_incident_update': 'campuspulse.read',
};
const TOOL_ROLES = {
    'post_incident_update': 'operator',
};
const METHOD_SCOPES = {
    'server/discover': null,          // capability discovery: authenticated, no scope
    'tools/list': 'campuspulse.read',
    'resources/list': 'campuspulse.read',
    'resources/read': 'campuspulse.read',
    'prompts/list': 'campuspulse.read',
    'prompts/get': 'campuspulse.read',
    'subscriptions/listen': 'campuspulse.read',
};

/** Which scope does this exact call need? Tool name wins over method. */
function requiredScopeFor(method, name) {
    if (method === 'tools/call') {
        // Unknown tool => deny by default. Never fall through to a read scope.
        return TOOL_SCOPES[name] ?? '\u0000deny';
    }
    if (method in METHOD_SCOPES) return METHOD_SCOPES[method];
    return '\u0000deny';
}

// ------------------------------------------------------------- JWKS with TTL

let jwksCache = { keys: [], fetchedAt: 0 };
const JWKS_TTL_MS = 5 * 60 * 1000;

async function getKey(kid) {
    const stale = Date.now() - jwksCache.fetchedAt > JWKS_TTL_MS;
    let hit = jwksCache.keys.find(k => k.kid === kid);
    // Cache, but re-fetch on an unknown kid: that is how key rotation is
    // survived without a restart, and why a JWKS cache needs both a TTL and a
    // miss-triggered refresh with its own rate limit.
    if (!hit || stale) {
        try {
            const res = await fetch(JWKS_URI);
            const body = await res.json();
            jwksCache = { keys: body.keys ?? [], fetchedAt: Date.now() };
            hit = jwksCache.keys.find(k => k.kid === kid);
        } catch { /* fall through to whatever is cached */ }
    }
    return hit ?? null;
}

// ------------------------------------------------------------ token validation

const ALLOWED_ALGS = new Set(['RS256']);   // matches what verify() below implements

async function validate(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return { ok: false, code: 401, reason: 'malformed token' };

    let header, payload;
    try {
        header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    } catch {
        return { ok: false, code: 401, reason: 'undecodable token' };
    }
    if (!header || typeof header !== 'object' || Array.isArray(header) ||
        !payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return { ok: false, code: 401, reason: 'JWT header and payload must be objects' };
    }

    if (!ALLOWED_ALGS.has(header.alg)) {
        return { ok: false, code: 401, reason: 'unacceptable signing algorithm', header, payload };
    }
    const jwk = await getKey(header.kid);
    if (!jwk) return { ok: false, code: 401, reason: 'unknown signing key', header, payload };

    let sigOk = false;
    try {
        const v = createVerify('RSA-SHA256');
        v.update(`${parts[0]}.${parts[1]}`);
        sigOk = v.verify(createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'));
    } catch { sigOk = false; }
    if (!sigOk) return { ok: false, code: 401, reason: 'signature verification failed', header, payload };

    if (payload.iss !== AS_ISSUER) {
        return { ok: false, code: 401, reason: 'issuer mismatch', header, payload };
    }

    const auds = Array.isArray(payload.aud) ? payload.aud : payload.aud === undefined ? [] : [payload.aud];
    if (!auds.includes(RESOURCE)) {
        return {
            ok: false, code: 401, header, payload,
            reason: 'audience mismatch',
        };
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp + SKEW <= now) {
        return { ok: false, code: 401, reason: `token expired ${now - (payload.exp ?? 0)}s ago`, header, payload };
    }
    if (typeof payload.nbf === 'number' && payload.nbf - SKEW > now) {
        return { ok: false, code: 401, reason: 'token not yet valid', header, payload };
    }

    return {
        ok: true, header, payload,
        // RFC 6749 §3.3: scope is a SPACE-delimited string. Some providers use
        // an `scp` array instead. Nothing else is a valid separator.
        scopes: Array.isArray(payload.scp)
            ? payload.scp
            : String(payload.scope ?? payload.scp ?? '').split(' ').filter(Boolean),
        roles: Array.isArray(payload.roles) ? payload.roles : [],
    };
}

// ------------------------------------------------------------------- logging

/**
 * actor -> tool -> arguments-shape -> decision -> result.
 * Week 9 grades this log. Write it now so you are not retrofitting it later.
 * Never log the token itself; log `jti` so a specific credential is traceable
 * without the log becoming a credential store.
 */
function audit(entry) {
    console.log(JSON.stringify({ ts: new Date().toISOString(), ...entry }));
}

// -------------------------------------------------------------------- server

function readBody(req) {
    return new Promise(resolve => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks)));
    });
}

function proxy(req, bodyBuf, res) {
    if (UPSTREAM === 'stub') {
        // Lets Part 5 run even if the Week 7 server is not up. It answers the
        // shape, not the content — enough to see the authorization result.
        let parsed = {};
        try { parsed = JSON.parse(bodyBuf.toString() || '{}'); } catch { /* ignore */ }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: parsed.id ?? 1,
            result: { stub: true, method: parsed.method ?? null, note: 'MCP_UPSTREAM=stub; authorization succeeded' },
        }));
        return;
    }
    const target = new URL(UPSTREAM);
    const up = httpRequest(
        {
            hostname: target.hostname,
            port: target.port,
            path: target.pathname,
            method: req.method,
            headers: { ...req.headers, host: target.host, 'content-length': bodyBuf.length },
        },
        upRes => {
            res.writeHead(upRes.statusCode, upRes.headers);
            upRes.pipe(res);
        },
    );
    up.on('error', e => {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
            error: 'upstream_unavailable',
            detail: e.message,
            hint: `Start the Week 7 MCP server (npm run start:http in samples/mcp-starter) or run this proxy with MCP_UPSTREAM=stub`,
        }));
    });
    up.end(bodyBuf);
}

const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // ---- RFC 9728 Protected Resource Metadata ------------------------------
    if (url.pathname === PRM_PATH || url.pathname === `${PRM_PATH}/mcp`) {
        res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=3600' });
        // NOTE what is deliberately NOT here: `jwks_uri`. In RFC 9728 that field
        // names keys the RESOURCE uses to sign its own responses — it is not the
        // authorization server's token-signing JWKS. A client finds those by
        // following `authorization_servers` and reading that server's metadata.
        // Publishing the AS's JWKS here is a common and confusing mistake.
        return res.end(JSON.stringify({
            resource: RESOURCE,
            authorization_servers: [AS_ISSUER],
            scopes_supported: ['campuspulse.read', 'campuspulse.incident.write'],
            bearer_methods_supported: ['header'],
            resource_documentation: 'https://campuspulse.example/docs/mcp',
        }, null, 2));
    }

    if (url.pathname === '/healthz') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ status: 'ok', authorization: 'oauth2', resource: RESOURCE, issuer: AS_ISSUER }));
    }

    if (url.pathname !== '/mcp') {
        res.writeHead(404, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'not_found' }));
    }

    const challenge = extra =>
        [`Bearer resource_metadata="http://${HOST}:${PORT}${PRM_PATH}"`, ...extra].join(', ');

    // ---- 0. the routing headers are not optional ---------------------------
    // Spec 2026-07-28 requires `Mcp-Method`, and `Mcp-Name` on any request that
    // names a target. An authorization proxy MUST NOT infer policy from a body
    // it does not control — if the header is absent we cannot police the call,
    // so we refuse it rather than guess.
    const methodHeader = req.headers['mcp-method'] ?? null;
    if (!methodHeader) {
        audit({ decision: 'deny', status: 400, reason: 'missing_mcp_method_header' });
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({
            error: 'invalid_request',
            error_description: 'Mcp-Method header is required; this proxy will not derive authorization policy from the request body alone.',
        }));
    }

    // ---- 1. is there a token at all? ---------------------------------------
    const auth = req.headers.authorization ?? '';
    if (!auth.toLowerCase().startsWith('bearer ')) {
        // Name the scope this specific call needs, so the client can request
        // least privilege rather than everything in `scopes_supported`.
        const wanted = requiredScopeFor(methodHeader, req.headers['mcp-name'] ?? null);
        const scopeHint = wanted && wanted !== '\u0000deny' ? wanted : 'campuspulse.read';
        audit({ decision: 'deny', status: 401, reason: 'no_bearer_token', method: methodHeader, name: req.headers['mcp-name'] ?? null });
        res.writeHead(401, {
            'www-authenticate': challenge([`scope="${scopeHint}"`]),
            'content-type': 'application/json',
        });
        return res.end(JSON.stringify({
            error: 'unauthorized',
            error_description: 'This MCP server requires an OAuth 2.1 access token. Start at the resource_metadata URL.',
        }));
    }

    // ---- 2. is the token real, current, and MINE? --------------------------
    const result = await validate(auth.slice(7).trim());
    if (!result.ok) {
        audit({
            decision: 'deny', status: 401, reason: result.reason,
            jti: result.payload?.jti ?? null, sub: result.payload?.sub ?? null,
            method: req.headers['mcp-method'] ?? null, name: req.headers['mcp-name'] ?? null,
        });
        res.writeHead(401, {
            'www-authenticate': challenge([`error="invalid_token"`, `error_description="${result.reason}"`]),
            'content-type': 'application/json',
        });
        return res.end(JSON.stringify({ error: 'invalid_token', error_description: result.reason }));
    }

    const bodyBuf = await readBody(req);

    // ---- 3. does the header agree with the body? ---------------------------
    const method = req.headers['mcp-method'] ?? null;
    const name = req.headers['mcp-name'] ?? null;
    let body = {};
    try { body = JSON.parse(bodyBuf.toString()); } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid_json' }));
    }
    if (!body || Array.isArray(body) || typeof body !== 'object' || typeof body.method !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid_request' }));
    }
    const bodyTarget = typeof body?.params?.name === 'string' ? body.params.name
        : typeof body?.params?.uri === 'string' ? body.params.uri
            : null;
    if (body.method && method && body.method !== method) {
        audit({ decision: 'deny', status: 400, reason: 'header_body_method_mismatch', header: method, body: body.method, sub: result.payload.sub });
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid_request', error_description: `Mcp-Method: ${method} but body.method: ${body.method}` }));
    }
    if ((bodyTarget || name) && bodyTarget !== name) {
        audit({ decision: 'deny', status: 400, reason: 'header_body_target_mismatch', header: name, body: bodyTarget, sub: result.payload.sub });
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid_request', error_description: `Mcp-Name: ${name} but body target: ${bodyTarget}` }));
    }

    // ---- 4. may THIS subject invoke THIS tool? -----------------------------
    const effectiveMethod = method;
    const effectiveName = name;
    const needed = requiredScopeFor(effectiveMethod, effectiveName);
    const neededRole = effectiveMethod === 'tools/call' ? (TOOL_ROLES[effectiveName] ?? null) : null;
    // Argument NAMES only. Never values — an audit log full of argument values
    // is a copy of your database with a search box on it.
    const argShape = Object.keys(body?.params?.arguments ?? {}).sort();

    if (needed === '\u0000deny') {
        audit({ decision: 'deny', status: 403, reason: 'no_policy_for_target', method: effectiveMethod, name: effectiveName, args: argShape, sub: result.payload.sub });
        res.writeHead(403, {
            'www-authenticate': challenge([`error="insufficient_scope"`, `error_description="no authorization policy covers this target"`]),
            'content-type': 'application/json',
        });
        return res.end(JSON.stringify({ error: 'insufficient_scope', error_description: 'deny by default: this target has no policy entry' }));
    }

    if (needed && !result.scopes.includes(needed)) {
        audit({
            decision: 'deny', status: 403, reason: 'insufficient_scope',
            required: needed, granted: result.scopes,
            method: effectiveMethod, name: effectiveName, args: argShape,
            sub: result.payload.sub, jti: result.payload.jti,
        });
        res.writeHead(403, {
            'www-authenticate': challenge([`error="insufficient_scope"`, `scope="${needed}"`]),
            'content-type': 'application/json',
        });
        return res.end(JSON.stringify({
            error: 'insufficient_scope',
            error_description: `${effectiveName ?? effectiveMethod} requires ${needed}`,
            required_scope: needed,
            granted_scope: result.scopes,
        }));
    }

    // The second gate. Scope said the CLIENT may ask; role says whether this
    // USER may. A step-up authorization cannot fix this one — the answer is no
    // until an administrator changes it — so there is no `scope` hint here.
    if (neededRole && !result.roles.includes(neededRole)) {
        audit({
            decision: 'deny', status: 403, reason: 'insufficient_role',
            required_role: neededRole, roles: result.roles,
            method: effectiveMethod, name: effectiveName, args: argShape,
            sub: result.payload.sub, jti: result.payload.jti,
        });
        res.writeHead(403, {
            'www-authenticate': challenge([`error="insufficient_permission"`, `error_description="${effectiveName} requires the ${neededRole} role"`]),
            'content-type': 'application/json',
        });
        return res.end(JSON.stringify({
            error: 'insufficient_permission',
            error_description: `${effectiveName} requires the ${neededRole} role`,
            required_role: neededRole,
            roles: result.roles,
        }));
    }

    // ---- 5. allowed ---------------------------------------------------------
    audit({
        decision: 'allow', status: 200,
        sub: result.payload.sub, jti: result.payload.jti, azp: result.payload.azp ?? result.payload.client_id,
        roles: result.roles, granted: result.scopes, required: needed, required_role: neededRole,
        method: effectiveMethod, name: effectiveName, args: argShape,
        expires_in: result.payload.exp - Math.floor(Date.now() / 1000),
    });

    // ---- 5a. the long-lived case -------------------------------------------
    if (effectiveMethod === 'subscriptions/listen') {
        return supervisedStream(res, result.payload);
    }

    proxy(req, bodyBuf, res);
});

/**
 * A SYNTHETIC long-lived stream, generated here rather than proxied.
 *
 * This is NOT an implementation of `subscriptions/listen` as specified in MCP
 * revision 2026-07-28 — it does not emit `notifications/subscriptions/*` or any
 * JSON-RPC notification shape. It is an authorization harness: the smallest
 * thing that makes the *lifetime* of an authorization decision observable in a
 * 35-minute lab. What is being demonstrated is the collision between a
 * point-in-time decision and a duration, not the subscription protocol.
 *
 * Your own implementation should terminate a real stream the same way.
 */
function supervisedStream(res, claims) {
    res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-store',
        connection: 'keep-alive',
    });
    const opened = Math.floor(Date.now() / 1000);
    res.write(`event: open\ndata: ${JSON.stringify({ sub: claims.sub, exp: claims.exp, expires_in: claims.exp - opened, enforcing: ENFORCE_STREAM_EXPIRY })}\n\n`);

    let n = 0;
    const beat = setInterval(() => {
        const now = Math.floor(Date.now() / 1000);
        const remaining = claims.exp - now;
        if (remaining <= 0 && ENFORCE_STREAM_EXPIRY) return;
        res.write(`event: heartbeat\ndata: ${JSON.stringify({ n: ++n, token_expires_in: remaining, still_streaming: true })}\n\n`);
    }, 2000);

    const expiry = ENFORCE_STREAM_EXPIRY ? setTimeout(() => {
        const age = Math.floor(Date.now() / 1000) - opened;
        audit({ decision: 'terminate', status: 200, reason: 'token_expired_mid_stream', sub: claims.sub, jti: claims.jti, stream_age_s: age });
        clearInterval(beat);
        res.end(`event: token_expired\ndata: ${JSON.stringify({ error: 'invalid_token', error_description: 'access token expired; re-authorize and reconnect', stream_age_s: age })}\n\n`);
    }, Math.max(0, claims.exp * 1000 - Date.now())) : null;
    res.on('close', () => { clearInterval(beat); clearTimeout(expiry); });
}

server.listen(PORT, HOST, () => {
    console.error([
        '',
        '  CampusPulse MCP — authorization proxy (Week 8)',
        `  resource : ${RESOURCE}`,
        `  metadata : http://${HOST}:${PORT}${PRM_PATH}`,
        `  issuer   : ${AS_ISSUER}`,
        `  jwks     : ${JWKS_URI}`,
        `  upstream : ${UPSTREAM}`,
        '',
        '  policy:',
        ...Object.entries(TOOL_SCOPES).map(([t, s]) =>
            `    tools/call ${t.padEnd(24)} -> ${s}${TOOL_ROLES[t] ? ` + role:${TOOL_ROLES[t]}` : ''}`),
        '    everything else                     -> deny by default',
        '',
    ].join('\n'));
});
