/**
 * expiry-mid-connection.mjs — where Week 7 and Week 8 collide.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, Lab Part 6. Zero dependencies.
 *
 *   node expiry-mid-connection.mjs --ttl 12
 *
 * THE PROBLEM
 *
 * An access token has a lifetime measured in minutes. A `subscriptions/listen`
 * stream — the long-lived POST stream that replaced `resources/subscribe` in
 * MCP spec revision 2026-07-28 — has a lifetime measured in hours. There is
 * exactly ONE authorization decision, taken when the stream opens.
 *
 * So: what is the authorization state of minute 47 of a stream opened with a
 * 15-minute token?
 *
 * If nobody supervises the stream, the answer is "whatever it was at minute 0",
 * which means a revoked user keeps receiving data, and your audit log says the
 * last decision was `allow`. That is not a hypothetical; it is the default
 * behaviour of every naive reverse proxy.
 *
 * WHAT THIS IS NOT
 *
 * The stream the proxy answers with is a SYNTHETIC authorization harness, not
 * an implementation of `subscriptions/listen`. It emits `open`, `heartbeat`,
 * and `token_expired` events rather than JSON-RPC notifications, because what
 * is being measured is the LIFETIME of an authorization decision, not the
 * subscription protocol. Your own server should terminate a real stream the
 * same way.
 *
 * Run this twice:
 *   ENFORCE_STREAM_EXPIRY=0 node mcp-auth-proxy.mjs   -> the bug
 *   ENFORCE_STREAM_EXPIRY=1 node mcp-auth-proxy.mjs   -> the fix
 *
 * Both runs are required HW7 evidence.
 */

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (!a.startsWith('--')) continue;
    const next = process.argv[i + 1];
    if (next && !next.startsWith('--')) { args.set(a.slice(2), next); i++; } else { args.set(a.slice(2), true); }
}

const AS = args.get('as') ?? 'http://127.0.0.1:9100';
const MCP = args.get('mcp') ?? 'http://127.0.0.1:8930/mcp';
const TTL = Number(args.get('ttl') ?? 12);
const WATCH = Number(args.get('watch') ?? TTL + 10);
const PROTOCOL_VERSION = '2026-07-28';

const minted = await (await fetch(`${AS}/mint?ttl=${TTL}`)).json();
const claims = JSON.parse(Buffer.from(minted.token.split('.')[1], 'base64url').toString());
const t0 = Date.now();
const el = () => `t+${String(Math.round((Date.now() - t0) / 1000)).padStart(3)}s`;

console.log(`
token minted with a ${TTL}-second lifetime
  exp ${claims.exp}  (${new Date(claims.exp * 1000).toISOString()})
  scope ${claims.scope}

opening a subscriptions/listen stream. Watching for ${WATCH}s.
`);

const res = await fetch(MCP, {
    method: 'POST',
    headers: {
        'content-type': 'application/json',
        // Spec 2026-07-28: a POST may be answered with JSON or an SSE stream,
        // so a conformant client advertises both.
        accept: 'application/json, text/event-stream',
        'Mcp-Method': 'subscriptions/listen',
        'Mcp-Protocol-Version': PROTOCOL_VERSION,
        authorization: `Bearer ${minted.token}`,
    },
    body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'subscriptions/listen',
        params: {
            _meta: {
                'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
                'io.modelcontextprotocol/clientInfo': { name: 'week08-expiry', version: '1.0.0' },
                'io.modelcontextprotocol/clientCapabilities': {},
            },
        },
    }),
});

console.log(`${el()}  stream opened: HTTP ${res.status} ${res.headers.get('content-type')}`);
if (!res.ok || !res.headers.get('content-type')?.includes('text/event-stream')) {
    throw new Error(`Expected an authorized SSE stream, not HTTP ${res.status}`);
}

const timer = setTimeout(() => {
    console.log(`\n${el()}  watch window over — the stream is STILL OPEN.`);
    console.log('       Authorization was decided once, at t+0, and never revisited.');
    console.log('       This is the failure mode. Restart the proxy with');
    console.log('       ENFORCE_STREAM_EXPIRY=1 and run this again.\n');
    process.exit(0);
}, WATCH * 1000);

let sawExpiry = false;
const reader = res.body.getReader();
const dec = new TextDecoder();
let buf = '';
while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\n\n')) !== -1) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const event = /event: (.+)/.exec(raw)?.[1] ?? 'message';
        const data = /data: (.+)/.exec(raw)?.[1] ?? '';
        if (event === 'token_expired') {
            sawExpiry = true;
            console.log(`${el()}  ${event}  ${data}`);
        } else {
            console.log(`${el()}  ${event.padEnd(14)} ${data}`);
        }
    }
}

clearTimeout(timer);
console.log(
    sawExpiry
        ? `\n${el()}  stream CLOSED by the authorization proxy at token expiry.\n       The client must re-authorize and reconnect. Correct behaviour.\n`
        : `\n${el()}  stream ended without an expiry event.\n`,
);
