import test from 'node:test';
import assert from 'node:assert/strict';
import { freePort, start, run } from '../../week07/samples/test-support.mjs';

// Build samples/mcp-starter first. This suite deliberately never uses the stub.
test('slide client walks reach the real memory-only Week 7 backend', async t => {
    const backend = await start('samples/mcp-starter/dist/http.js', { MCP_HOST: '127.0.0.1' });
    t.after(backend.stop);
    const health = await (await fetch(`${backend.url}/healthz`)).json();
    assert.equal(health.store, 'memory');
    const port = await freePort();
    const resource = `http://127.0.0.1:${port}/mcp`;
    const issuer = await start('weeks/week08/samples/authz-server.mjs', { MCP_RESOURCE: resource }, [], '/jwks.json');
    t.after(issuer.stop);
    const proxy = await start('weeks/week08/samples/mcp-auth-proxy.mjs', {
        MCP_RESOURCE: resource, AS_ISSUER: issuer.url, MCP_UPSTREAM: `${backend.url}/mcp`,
    }, [], '/healthz', port);
    t.after(proxy.stop);

    for (const [tool, role, status] of [
        ['list_service_status', 'viewer', 200],
        ['get_incident', 'viewer', 200],
        ['post_incident_update', 'viewer', 403],
        ['post_incident_update', 'operator', 200],
    ]) await t.test(`${role} calls ${tool}: ${status}`, async () => {
        const result = await run('weeks/week08/samples/mcp-client-walk.mjs', [
            '--mcp', resource, '--tool', tool, '--login-as', role,
        ]);
        assert.equal(result.code, 0, result.output);
        assert.match(result.output, new RegExp(`RESULT  401 -> ${status}`));
        assert.doesNotMatch(result.output, /STUB|operation failed/);
    });
    await t.test('operator update actually appears in the incident timeline', async () => {
        const { token } = await (await fetch(`${issuer.url}/mint?variant=operator`)).json();
        const response = await fetch(resource, {
            method: 'POST',
            headers: {
                'content-type': 'application/json', accept: 'application/json, text/event-stream',
                authorization: `Bearer ${token}`, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'get_incident',
                'Mcp-Protocol-Version': '2026-07-28',
            },
            body: JSON.stringify({
                jsonrpc: '2.0', id: 2, method: 'tools/call',
                params: { name: 'get_incident', arguments: { ref: 'INC-2026-0016' }, _meta: {
                    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                    'io.modelcontextprotocol/clientInfo': { name: 'week08-demo-check', version: '1.0.0' },
                    'io.modelcontextprotocol/clientCapabilities': {},
                } },
            }),
        });
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.ok(!body.error && !body.result?.isError, JSON.stringify(body));
        assert.match(JSON.stringify(body.result), /Week 8 lab: authorization verified end to end/);
        const audit = proxy.output().split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
        assert.ok(audit.some(entry => entry.name === 'post_incident_update' && entry.decision === 'deny'));
        assert.ok(audit.some(entry => entry.name === 'post_incident_update' && entry.decision === 'allow'));
    });
});
