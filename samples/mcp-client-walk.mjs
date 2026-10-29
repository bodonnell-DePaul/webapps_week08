/**
 * mcp-client-walk.mjs — the 401 -> authorized progression, captured.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, Lab Part 5. Zero dependencies.
 *
 *   node mcp-client-walk.mjs
 *   node mcp-client-walk.mjs --login-as operator
 *   node mcp-client-walk.mjs --tool post_incident_update
 *
 * This is an MCP client doing exactly what MCP specification 2026-07-28
 * §Authorization requires, in order, with nothing skipped:
 *
 *   1. call the MCP server with no token        -> expect 401
 *   2. read `resource_metadata` from WWW-Authenticate
 *   3. GET the Protected Resource Metadata      (RFC 9728)
 *   4. GET the authorization server metadata    (OIDC Discovery / RFC 8414)
 *   5. authorization request: PKCE + `resource` (RFC 7636 + RFC 8707)
 *   6. validate `iss` on the authorization response (RFC 9207)
 *   7. token request: code + code_verifier + `resource`
 *   8. call the MCP server again with the token -> expect 200 or 403
 *
 * Step 6 is the one everybody skips. It is what stops a mix-up attack, where a
 * malicious authorization server hands your client a code that belongs to a
 * different, honest one.
 *
 * The browser step is automated here because a headless walk is reproducible
 * and a lab is 35 minutes. Use the complete browser demo for real sign-in.
 */

import { createHash, randomBytes } from 'node:crypto';

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (!a.startsWith('--')) continue;
    const next = process.argv[i + 1];
    if (next && !next.startsWith('--')) { args.set(a.slice(2), next); i++; } else { args.set(a.slice(2), true); }
}

const MCP = args.get('mcp') ?? 'http://127.0.0.1:8930/mcp';
const TOOL = args.get('tool') ?? 'list_service_status';
const LOGIN_AS = args.get('login-as') ?? 'viewer';
const REDIRECT = 'http://127.0.0.1:5173/callback';
const PROTOCOL_VERSION = '2026-07-28';
const b64url = b => Buffer.from(b).toString('base64url');

let step = 0;
const say = (title, detail) => {
    console.log(`\n${'-'.repeat(74)}\n[${++step}] ${title}`);
    if (detail) console.log(detail);
};

const META = {
    'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
    'io.modelcontextprotocol/clientInfo': { name: 'week08-walk', version: '1.0.0' },
    'io.modelcontextprotocol/clientCapabilities': {},
};

/** Sensible arguments per tool, so a 200 shows a real result rather than a schema error. */
const TOOL_ARGS = {
    list_service_status: { onlyImpacted: true },
    get_incident: { ref: 'INC-2026-0016' },
    post_incident_update: {
        ref: 'INC-2026-0016',
        body: 'Week 8 lab: authorization verified end to end.',
        // Synthetic classroom text must be visible in the public incident readback.
        isPublic: true,
        confirm: true,
    },
};

/** One MCP call. Header routing per 2026-07-28 (SEP-2243). */
function callTool(token, toolName) {
    return fetch(MCP, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            'Mcp-Method': 'tools/call',
            'Mcp-Name': toolName,
            'Mcp-Protocol-Version': PROTOCOL_VERSION,
            ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'tools/call',
            params: { name: toolName, arguments: TOOL_ARGS[toolName] ?? {}, _meta: META },
        }),
    });
}

// ---- 1. no token -----------------------------------------------------------
const unauth = await callTool(null, TOOL);
const wwwAuth = unauth.headers.get('www-authenticate') ?? '(none)';
say(
    `tools/call ${TOOL} with NO Authorization header`,
    `    HTTP ${unauth.status}\n    WWW-Authenticate: ${wwwAuth}\n    body: ${(await unauth.text()).slice(0, 160)}`,
);
if (unauth.status !== 401) {
    console.error('\n!! Expected 401. If you got 200, the proxy is not in the path — check the port.\n');
    process.exit(1);
}

// ---- 2/3. protected resource metadata --------------------------------------
const prmUrl = /resource_metadata="([^"]+)"/.exec(wwwAuth)?.[1];
if (!prmUrl) { console.error('no resource_metadata in the challenge'); process.exit(1); }
const prm = await (await fetch(prmUrl)).json();
say(`GET ${prmUrl}   (RFC 9728)`, JSON.stringify(prm, null, 2).split('\n').map(l => `    ${l}`).join('\n'));

// ---- 4. authorization server metadata --------------------------------------
// The spec requires clients to support BOTH discovery mechanisms. Try OAuth 2.0
// Authorization Server Metadata (RFC 8414) first, then OIDC Discovery.
const asBase = prm.authorization_servers[0];
let asMeta = null;
let asMetaUrl = null;
for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']) {
    try {
        const r = await fetch(`${asBase}${path}`);
        if (r.ok) { asMeta = await r.json(); asMetaUrl = `${asBase}${path}`; break; }
    } catch { /* try the next one */ }
}
if (!asMeta) { console.error(`no authorization server metadata at ${asBase}`); process.exit(1); }

// The issuer in the metadata document MUST match the server we asked
// (RFC 8414 §3.3 / OIDC Discovery §4.3). Skipping this is how a client ends up
// trusting a document served from somewhere it did not intend to talk to.
if (asMeta.issuer !== asBase) {
    console.error(`issuer mismatch: metadata says ${asMeta.issuer}, PRM named ${asBase}`);
    process.exit(1);
}

say(
    `GET ${asMetaUrl}`,
    [
        `    issuer                        ${asMeta.issuer}   (matches the PRM entry)`,
        `    authorization_endpoint        ${asMeta.authorization_endpoint}`,
        `    token_endpoint                ${asMeta.token_endpoint}`,
        `    jwks_uri                      ${asMeta.jwks_uri}`,
        `    code_challenge_methods        ${(asMeta.code_challenge_methods_supported ?? []).join(', ')}`,
        `    iss in auth response          ${asMeta.authorization_response_iss_parameter_supported}`,
    ].join('\n'),
);

// ---- 5. authorization request ----------------------------------------------
const verifier = b64url(randomBytes(32));
const challenge = b64url(createHash('sha256').update(verifier).digest());
const state = b64url(randomBytes(16));

// Least privilege: MCP spec 2026-07-28 says use the `scope` from the
// WWW-Authenticate challenge when the server provided one, and fall back to
// `scopes_supported` only when it did not. Asking for everything in the PRM is
// the lazy option and it is what over-broad grants look like in the wild.
const challengedScope = /(?:^|,\s*)scope="([^"]+)"/.exec(wwwAuth)?.[1] ?? null;
const wantScope = challengedScope ?? prm.scopes_supported.join(' ');

const authorize = new URL(asMeta.authorization_endpoint);
authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: 'campuspulse-mcp-client',
    redirect_uri: REDIRECT,
    scope: `openid ${wantScope}`,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    // RFC 8707 — in BOTH requests. It is what makes `aud` mean something, and
    // it is a MUST for MCP clients.
    resource: prm.resource,
    login_as: LOGIN_AS,
}).toString();
say(
    'authorization request (PKCE + resource)',
    [
        `    code_challenge_method=S256`,
        `    code_challenge=${challenge}`,
        `    resource=${prm.resource}`,
        `    scope=openid ${wantScope}`,
        `           ^ ${challengedScope ? 'from the WWW-Authenticate challenge — least privilege' : 'from scopes_supported (no scope in the challenge)'}`,
        `    signed in as: ${LOGIN_AS}`,
    ].join('\n'),
);

// The lab AS renders a consent page containing the callback link; a real
// browser click produces the same redirect. We extract it rather than
// pretending a redirect happened.
const consent = await (await fetch(authorize)).text();
const callback = /<a href="([^"]+)">Approve/.exec(consent)?.[1]?.replace(/&amp;/g, '&');
if (!callback) { console.error('could not find the approval link on the consent page'); process.exit(1); }
const cb = new URL(callback);

// ---- 6. validate the authorization response --------------------------------
const returnedState = cb.searchParams.get('state');
const returnedIss = cb.searchParams.get('iss');
const stateOk = returnedState === state;
const issOk = returnedIss === asMeta.issuer;
say(
    'authorization response validation',
    [
        `    state   ${stateOk ? 'OK  ' : 'FAIL'} returned=${returnedState}`,
        `    iss     ${issOk ? 'OK  ' : 'FAIL'} returned=${returnedIss} expected=${asMeta.issuer}   (RFC 9207)`,
        `    code    ${cb.searchParams.get('code').slice(0, 12)}…  <- assume this leaked; PKCE is why that is survivable`,
    ].join('\n'),
);
if (!stateOk || !issOk) { console.error('refusing to exchange a code from an unvalidated response'); process.exit(1); }

// ---- 7. token request ------------------------------------------------------
const tokenRes = await fetch(asMeta.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: cb.searchParams.get('code'),
        redirect_uri: REDIRECT,
        client_id: 'campuspulse-mcp-client',
        code_verifier: verifier,
        resource: prm.resource,
    }),
});
const tokens = await tokenRes.json();
if (!tokenRes.ok) { console.error(`token endpoint said ${tokenRes.status}: ${JSON.stringify(tokens)}`); process.exit(1); }

const claims = JSON.parse(Buffer.from(tokens.access_token.split('.')[1], 'base64url').toString());
say(
    `POST ${asMeta.token_endpoint}   ->  HTTP ${tokenRes.status}`,
    [
        `    token_type    ${tokens.token_type}`,
        `    expires_in    ${tokens.expires_in}s`,
        `    scope         ${tokens.scope}`,
        `    id_token      ${tokens.id_token ? 'present (for the CLIENT — never send it to the API)' : 'absent'}`,
        '',
        '    access-token claims that decide the next request:',
        `      iss    ${claims.iss}`,
        `      aud    ${claims.aud}      <- must be ${prm.resource}`,
        `      sub    ${claims.sub}`,
        `      scope  ${claims.scope}`,
        `      roles  ${JSON.stringify(claims.roles)}`,
        `      exp    ${claims.exp}  (${new Date(claims.exp * 1000).toISOString()})`,
    ].join('\n'),
);

// ---- 8. the same call, now authorized --------------------------------------
const authed = await callTool(tokens.access_token, TOOL);
const bodyText = await authed.text();
let result;
try { result = JSON.parse(bodyText); } catch { result = null; }
const toolFailed = authed.status === 200 && (!result || result.error || result.result?.isError);
const incident = result?.result?.structuredContent?.incident;
say(
    `tools/call ${TOOL} WITH the access token`,
    [
        `    HTTP ${authed.status}`,
        authed.headers.get('www-authenticate') ? `    WWW-Authenticate: ${authed.headers.get('www-authenticate')}` : '',
        `    body: ${bodyText.slice(0, 300)}`,
        incident ? `    incident updates: ${JSON.stringify(incident.updates)}` : '',
    ].filter(Boolean).join('\n'),
);

console.log(`\n${'='.repeat(74)}`);
console.log(
    toolFailed
        ? 'RESULT  authorization allowed the request, but the MCP operation failed. Inspect the result; HTTP 200 alone is not success.'
        : authed.status === 200
        ? result.result?.stub
            ? 'RESULT  401 -> 200 (STUB). Policy allowed the request; no actual MCP tool ran.'
            : `RESULT  401 -> 200. The same call, the same server, one credential apart.`
        : authed.status === 403
            ? `RESULT  401 -> 403. Authentication succeeded; authorization did not.\n        Re-run with --login-as operator and read the difference.`
            : `RESULT  unexpected status ${authed.status}`,
);
console.log(`${'='.repeat(74)}\n`);
if (toolFailed || ![200, 403].includes(authed.status)) process.exitCode = 1;
