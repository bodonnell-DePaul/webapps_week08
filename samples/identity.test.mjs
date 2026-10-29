import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, createHmac, createPublicKey, randomBytes } from 'node:crypto';
import { courseRoot, freePort, start, run } from '../../week07/samples/test-support.mjs';

test('local issuer and OAuth proxy exercise authentication separately from permissions', async t => {
    const proxyPort = await freePort();
    const resource = `http://127.0.0.1:${proxyPort}/mcp`;
    const as = await start('weeks/week08/samples/authz-server.mjs', { MCP_RESOURCE: resource }, [], '/jwks.json');
    t.after(as.stop);
    const proxy = await start('weeks/week08/samples/mcp-auth-proxy.mjs', {
        AS_ISSUER: as.url, MCP_UPSTREAM: 'stub', MCP_RESOURCE: resource, CLOCK_SKEW: '0',
    }, [], '/healthz', proxyPort);
    t.after(proxy.stop);
    const token = async variant => (await (await fetch(`${as.url}/mint?variant=${variant}`)).json()).token;
    const call = (credential, name = 'list_service_status', overrides = {}) => fetch(`${proxy.url}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'mcp-method': 'tools/call', 'mcp-name': name,
            ...(credential ? { authorization: `Bearer ${credential}` } : {}), ...overrides },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: {} } }),
    });
    await t.test('missing credential provides protected-resource discovery', async () => {
        const res = await call();
        assert.equal(res.status, 401);
        assert.match(res.headers.get('www-authenticate'), /resource_metadata=/);
        const metadataUrl = /resource_metadata="([^"]+)"/.exec(res.headers.get('www-authenticate'))[1];
        const metadata = await (await fetch(metadataUrl)).json();
        assert.equal(metadata.resource, `${proxy.url}/mcp`);
        assert.deepEqual(metadata.authorization_servers, [as.url]);
        const claims = JSON.parse(Buffer.from((await token('valid')).split('.')[1], 'base64url'));
        assert.equal(claims.aud, metadata.resource);
        assert.equal(claims.iss, as.url);
        await res.text();
    });
    for (const [variant, expected] of [
        ['valid', 200], ['expired', 401], ['wrong-issuer', 401], ['wrong-audience', 401],
        ['not-yet-valid', 401], ['no-scope', 403], ['id-token', 401], ['stale-kid', 401],
    ]) await t.test(`token variant ${variant} returns ${expected}`, async () => {
        const res = await call(await token(variant));
        assert.equal(res.status, expected);
        await res.text();
    });
    for (const [variant, expected] of [['operator', 200], ['viewer-write', 403], ['operator-read', 403]]) {
        await t.test(`${variant}: role and scope both required for writes`, async () => {
            const res = await call(await token(variant), 'post_incident_update');
            assert.equal(res.status, expected);
            await res.text();
        });
    }
    await t.test('tampered and null JWTs reject without killing server', async () => {
        const good = await token('valid');
        const parts = good.split('.');
        parts[1] = Buffer.from('{"roles":["operator"]}').toString('base64url');
        assert.equal((await call(parts.join('.'))).status, 401);
        assert.equal((await call('bnVsbA.bnVsbA.eA')).status, 401);
        assert.equal((await fetch(`${proxy.url}/healthz`)).status, 200);
    });
    await t.test('missing or mismatched routing headers never inherit body permission', async () => {
        const good = await token('valid');
        assert.equal((await call(good, 'list_service_status', { 'mcp-name': '' })).status, 400);
        assert.equal((await call(good, 'list_service_status', { 'mcp-name': 'get_incident' })).status, 400);
    });
    await t.test('alg none and RSA-to-HMAC confusion both fail the configured allow-list', async () => {
        const original = (await token('valid')).split('.');
        const header = JSON.parse(Buffer.from(original[0], 'base64url'));
        const { keys } = await (await fetch(`${as.url}/jwks.json`)).json();
        const publicKey = createPublicKey({ key: keys.find(key => key.kid === header.kid), format: 'jwk' })
            .export({ type: 'spki', format: 'pem' });
        for (const alg of ['none', 'HS256']) {
            const encoded = Buffer.from(JSON.stringify({ ...header, alg })).toString('base64url');
            const input = `${encoded}.${original[1]}`;
            const signature = alg === 'none' ? '' : createHmac('sha256', publicKey).update(input).digest('base64url');
            const forged = `${input}.${signature}`;
            const response = await call(forged);
            assert.equal(response.status, 401);
            assert.match(await response.text(), /unacceptable signing algorithm/);
            const checked = await run('weeks/week08/samples/validate-token.mjs', [
                '--as', as.url, '--audience', resource, '--token', forged,
            ]);
            assert.equal(checked.code, 1, checked.output);
            assert.match(checked.output, /unacceptable signing algorithm/);
        }
    });
    await t.test('PKCE CLI actually executes wrong-verifier and replay cases', async () => {
        const result = await run('weeks/week08/samples/pkce-negative.mjs', [], { AS: as.url, MCP_RESOURCE: resource });
        assert.equal(result.code, 0, result.output);
        assert.equal((result.output.match(/HTTP 200/g) ?? []).length, 1);
        assert.equal((result.output.match(/HTTP 400/g) ?? []).length, 4);
        assert.match(result.output, /PKCE verification failed/);
        assert.match(result.output, /unknown or already-redeemed code/);
    });
    await t.test('refresh rotation binds client and revokes reused token family', async () => {
        const verifier = randomBytes(32).toString('base64url');
        const request = new URL(`${as.url}/authorize`);
        request.search = new URLSearchParams({
            response_type: 'code', client_id: 'campuspulse-web', redirect_uri: 'http://127.0.0.1:5173/callback',
            code_challenge: createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256', scope: 'openid offline_access campuspulse.read', resource,
        });
        const page = await (await fetch(request)).text();
        const code = new URL(/<a href="([^"]+)">Approve/.exec(page)[1].replaceAll('&amp;', '&')).searchParams.get('code');
        const redeem = form => fetch(`${as.url}/token`, { method: 'POST', body: new URLSearchParams(form) });
        const issued = await (await redeem({
            grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'campuspulse-web',
            redirect_uri: 'http://127.0.0.1:5173/callback', resource,
        })).json();
        assert.ok(issued.refresh_token);
        const refresh = (value, client = 'campuspulse-web') => redeem({
            grant_type: 'refresh_token', refresh_token: value, client_id: client,
        });
        assert.equal((await refresh(issued.refresh_token, 'different-client')).status, 400);
        const rotated = await (await refresh(issued.refresh_token)).json();
        assert.ok(rotated.refresh_token);
        assert.notEqual(rotated.refresh_token, issued.refresh_token);
        assert.equal((await refresh(issued.refresh_token)).status, 400);
        assert.equal((await refresh(rotated.refresh_token)).status, 400);
    });
    await t.test('introspection rejects future activation and key rotation remains verifiable', async () => {
        const future = await token('not-yet-valid');
        const introspection = await (await fetch(`${as.url}/introspect`, {
            method: 'POST', body: new URLSearchParams({ token: future }),
        })).json();
        assert.equal(introspection.active, false);
        const prior = await token('valid');
        const before = await (await fetch(`${as.url}/jwks.json`)).json();
        await fetch(`${as.url}/rotate`);
        const after = await (await fetch(`${as.url}/jwks.json`)).json();
        assert.equal(after.keys.length, before.keys.length + 1);
        assert.equal((await call(prior)).status, 200);
        assert.equal((await call(await token('valid'))).status, 200);
    });
    await t.test('tamper CLI writes a forged token that the validator rejects', async () => {
        const dir = join(courseRoot, 'weeks', 'week08', 'samples', `.tamper-${process.pid}`);
        mkdirSync(dir, { recursive: true });
        try {
            const file = join(dir, 'forged.txt');
            const forged = await run('weeks/week08/samples/tamper.mjs', ['--as', as.url, '--out', file]);
            assert.equal(forged.code, 0, forged.output);
            const checked = await run('weeks/week08/samples/validate-token.mjs', [
                '--as', as.url, '--audience', resource, '--token-file', file, '--scope', 'campuspulse.incident.write',
            ]);
            assert.equal(checked.code, 1);
            assert.match(checked.output, /signature verification failed/);
        } finally { rmSync(dir, { recursive: true, force: true }); }
    });
    await t.test('validator CLI validates and rejects representative fixtures', async () => {
        for (const [variant, code, verdict] of [
            ['valid', 0, 'ACCEPT 200'], ['expired', 1, 'REJECT 401'],
            ['wrong-issuer', 1, 'REJECT 401'], ['wrong-audience', 1, 'REJECT 401'],
            ['not-yet-valid', 1, 'REJECT 401'], ['no-scope', 1, 'REJECT 403'],
            ['id-token', 1, 'REJECT 401'], ['stale-kid', 1, 'REJECT 401'],
        ]) {
            const result = await run('weeks/week08/samples/validate-token.mjs', [
                '--as', as.url, '--audience', resource, '--variant', variant, '--scope', 'campuspulse.read',
            ]);
            assert.equal(result.code, code, result.output);
            assert.ok(result.output.includes(verdict), result.output);
            if (variant === 'valid') assert.equal((result.output.match(/PASS /g) ?? []).length, 8);
        }
    });
    await t.test('decode-only is explicitly not validation', async () => {
        const result = await run('weeks/week08/samples/validate-token.mjs', [
            '--as', as.url, '--variant', 'valid', '--decode-only',
        ]);
        assert.equal(result.code, 0, result.output);
        assert.match(result.output, /stopping before validation/);
        assert.doesNotMatch(result.output, /ACCEPT 200/);
    });
    await t.test('PKCE URL builder uses the discovered endpoints', async () => {
        const result = await run('weeks/week08/samples/pkce.mjs', [
            '--discovery', `${as.url}/.well-known/openid-configuration`, '--resource', resource,
        ]);
        assert.equal(result.code, 0);
        assert.match(result.output, /code_challenge_method=S256/);
        assert.ok(result.output.includes(`${as.url}/authorize`));
    });
    await t.test('OAuth client walk executes viewer denial and operator allowance', async () => {
        for (const role of ['viewer', 'operator']) {
            const result = await run('weeks/week08/samples/mcp-client-walk.mjs', [
                '--mcp', `${proxy.url}/mcp`, '--login-as', role, '--tool', 'post_incident_update',
            ]);
            assert.equal(result.code, 0, result.output);
            assert.match(result.output, role === 'viewer' ? /HTTP 403/ : /HTTP 200/);
        }
    });
    await t.test('expiry runner observes synthetic stream termination', async () => {
        const result = await run('weeks/week08/samples/expiry-mid-connection.mjs', [
            '--as', as.url, '--mcp', `${proxy.url}/mcp`, '--ttl', '2', '--watch', '6',
        ]);
        assert.equal(result.code, 0, result.output);
        assert.match(result.output, /stream CLOSED/);
    });
    await t.test('unenforced synthetic stream visibly outlives its credential', async () => {
        const unsafePort = await freePort();
        const unsafeResource = `http://127.0.0.1:${unsafePort}/mcp`;
        const unsafeAs = await start('weeks/week08/samples/authz-server.mjs', { MCP_RESOURCE: unsafeResource }, [], '/jwks.json');
        t.after(unsafeAs.stop);
        const unsafe = await start('weeks/week08/samples/mcp-auth-proxy.mjs', {
            AS_ISSUER: unsafeAs.url, MCP_UPSTREAM: 'stub', MCP_RESOURCE: unsafeResource,
            CLOCK_SKEW: '0', ENFORCE_STREAM_EXPIRY: '0',
        }, [], '/healthz', unsafePort);
        try {
            const result = await run('weeks/week08/samples/expiry-mid-connection.mjs', [
                '--as', unsafeAs.url, '--mcp', `${unsafe.url}/mcp`, '--ttl', '2', '--watch', '5',
            ]);
            assert.equal(result.code, 0, result.output);
            assert.match(result.output, /stream is STILL OPEN/);
            assert.match(result.output, /token_expires_in":-/);
        } finally { await unsafe.stop(); }
    });
});

test('HAR sanitization handles five locations, encoded bodies and short opaque values', async t => {
    const dir = join(courseRoot, 'weeks', 'week08', 'samples', `.audit-${process.pid}`);
    mkdirSync(join(dir, 'evidence'), { recursive: true });
    t.after(() => rmSync(dir, { force: true, recursive: true }));
    const secret = 'tiny!';
    writeFileSync(join(dir, 'known.txt'), secret);
    const raw = { log: { entries: [{
        request: {
            url: `http://127.0.0.1/callback?code=${encodeURIComponent(secret)}`,
            queryString: [{ name: 'code', value: secret }],
            headers: [{ name: 'Cookie', value: `sid=${secret}` }], cookies: [{ name: 'sid', value: secret }],
            postData: { text: `client_secret=${encodeURIComponent(secret)}&code=a%2Fb`,
                params: [{ name: 'code_verifier', value: secret }] },
        },
        response: { headers: [{ name: 'Location', value: `/callback?code=${secret}` }], cookies: [],
            content: { encoding: 'base64', text: Buffer.from(JSON.stringify({ access_token: secret })).toString('base64') } },
    }] } };
    writeFileSync(join(dir, 'raw.har'), JSON.stringify(raw));
    const sanitized = join(dir, 'evidence', 'clean.har');
    const result = await run('weeks/week08/samples/sanitize-har.mjs', [join(dir, 'raw.har'), sanitized]);
    assert.equal(result.code, 0, result.output);
    const text = readFileSync(sanitized, 'utf8');
    assert.ok(!text.includes(secret));
    assert.ok(!text.includes('a%2Fb'));
    assert.ok(!text.includes(Buffer.from(JSON.stringify({ access_token: secret })).toString('base64')));
    const clean = await run('weeks/week08/samples/scan-evidence.mjs', [join(dir, 'evidence'), '--secrets-from', join(dir, 'known.txt')]);
    assert.equal(clean.code, 0, clean.output);
    writeFileSync(join(dir, 'evidence', 'leak.txt'), secret);
    const leaked = await run('weeks/week08/samples/scan-evidence.mjs', [join(dir, 'evidence'), '--secrets-from', join(dir, 'known.txt')]);
    assert.equal(leaked.code, 1);
});
