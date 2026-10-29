/**
 * tamper.mjs — change a claim, leave the signature alone, watch it fail.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, Lab Part 3.3. Zero dependencies, identical on every platform.
 *
 *   node tamper.mjs
 *   node tamper.mjs --claim roles --value '["operator"]'
 *
 * This is the single most useful thirty seconds in the week. A JWT's first two
 * segments are base64url, not encrypted. Anyone can rewrite them. What they
 * cannot do is produce a signature over the result, because that needs the
 * issuer's private key.
 *
 * So: take a genuine token, promote yourself from viewer to operator, and hand
 * the result to a validator. The decoder will show your new claims. The
 * validator will reject at check 3 and nowhere else.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (!a.startsWith('--')) continue;
    const next = process.argv[i + 1];
    if (next && !next.startsWith('--')) { args.set(a.slice(2), next); i++; } else { args.set(a.slice(2), true); }
}

const AS = args.get('as') ?? 'http://127.0.0.1:9100';
const OUT = args.get('out') ?? 'out/forged.txt';

const token = (await (await fetch(`${AS}/mint?variant=valid&raw`)).text()).trim();
const [h, p, s] = token.split('.');
const before = JSON.parse(Buffer.from(p, 'base64url').toString());

const after = { ...before };
if (args.get('claim')) {
    let v = args.get('value');
    try { v = JSON.parse(v); } catch { /* keep as string */ }
    after[args.get('claim')] = v;
} else {
    // The default promotion: viewer -> operator, read -> read + write.
    after.roles = ['operator'];
    after.scope = 'openid campuspulse.read campuspulse.incident.write';
}

const forged = `${h}.${Buffer.from(JSON.stringify(after)).toString('base64url')}.${s}`;
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, forged);

console.log(`
 before   roles=${JSON.stringify(before.roles)}  scope="${before.scope}"
 after    roles=${JSON.stringify(after.roles)}  scope="${after.scope}"

 header   untouched  (${h.length} chars)
 payload  rewritten  (${p.length} -> ${forged.split('.')[1].length} chars)
 signature untouched (${s.length} chars) — still signs the OLD payload

 written to ${OUT}

 now run:
   node validate-token.mjs --token-file ${OUT} --scope campuspulse.incident.write
`);
