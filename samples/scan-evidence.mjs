/**
 * scan-evidence.mjs — the check that actually decides your redaction grade.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, HW7 §5. Zero dependencies.
 *
 *   node scan-evidence.mjs evidence/
 *   node scan-evidence.mjs evidence/ --secrets-from raw-evidence/known-values.txt
 *
 * TWO PASSES, because they catch different things.
 *
 * PASS 1 — SHAPE. Finds anything that LOOKS like a credential: a three-segment
 * JWT, a private key block, a bearer header, a cloud key. Cheap, and it catches
 * the obvious mistake.
 *
 * PASS 2 — VALUES. Finds the specific strings YOU handled. This is the one that
 * matters, because an opaque access token, an authorization code, and a client
 * secret look like nothing in particular. A shape scan will never find them.
 *
 * `known-values.txt` is one secret per line — every code, token, verifier,
 * cookie value, and client secret that passed through your terminal during the
 * assignment. It lives in a GITIGNORED directory and is never submitted. Writing
 * it is itself the exercise: if you cannot list the credentials you handled, you
 * do not know what you might have leaked.
 *
 * Exit code 0 = clean, 1 = something was found. Wire it into CI if you like.
 */

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const args = process.argv.slice(2);
const root = args.find(a => !a.startsWith('--')) ?? 'evidence';
const secretsFile = args.includes('--secrets-from')
    ? args[args.indexOf('--secrets-from') + 1]
    : null;

const SHAPES = [
    [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'a complete JWT'],
    [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'a private key block'],
    [/\bAKIA[0-9A-Z]{16}\b/g, 'an AWS access key id'],
    [/\bgh[pousr]_[A-Za-z0-9]{36,}/g, 'a GitHub token'],
    [/^\s*authorization:\s*bearer\s+\S{20,}/gim, 'an unredacted Authorization header'],
    [/^\s*(?:set-)?cookie:\s*\S+=\S{20,}/gim, 'an unredacted cookie'],
    [/\b(?:client_secret|code_verifier)["'\s]*[:=]["'\s]*[A-Za-z0-9._~+/-]{16,}/gi, 'a credential assignment'],
];

function* walk(dir) {
    for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        const st = statSync(p);
        if (st.isDirectory()) yield* walk(p);
        else if (st.size < 40 * 1024 * 1024) yield p;
    }
}

if (!existsSync(root)) {
    console.error(`no such directory: ${root}`);
    process.exit(2);
}

const knownValues = secretsFile && existsSync(secretsFile)
    ? readFileSync(secretsFile, 'utf8').split(/\r?\n/).map(s => s.trim()).filter(Boolean)
    : [];

if (secretsFile && !existsSync(secretsFile)) {
    console.error(`--secrets-from: no such file: ${secretsFile}`);
    process.exit(2);
}

let findings = 0;
let scanned = 0;

for (const file of walk(root)) {
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    scanned++;
    const rel = relative(process.cwd(), file);

    for (const [re, label] of SHAPES) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(text)) !== null) {
            const line = text.slice(0, m.index).split('\n').length;
            console.log(`FOUND  ${rel}:${line}  ${label}`);
            findings++;
            if (re.lastIndex === m.index) re.lastIndex++;
        }
    }

    for (const secret of new Set(knownValues.flatMap(value => [
        value, encodeURIComponent(value), new URLSearchParams({ v: value }).toString().slice(2),
    ]))) {
        let idx = text.indexOf(secret);
        while (idx !== -1) {
            const line = text.slice(0, idx).split('\n').length;
            console.log(`FOUND  ${rel}:${line}  a value from your known-values list (${secret.length} chars)`);
            findings++;
            idx = text.indexOf(secret, idx + secret.length);
        }
    }
}

console.log('');
console.log(`scanned    ${scanned} file(s) under ${root}`);
console.log(`shape rules ${SHAPES.length}`);
console.log(`known values ${knownValues.length}${knownValues.length === 0 ? '  <-- pass --secrets-from; a shape scan alone is NOT sufficient' : ''}`);
console.log(findings === 0
    ? '\nRESULT  clean — no credential shapes and no known values found.\n'
    : `\nRESULT  ${findings} finding(s). Do not submit until this is zero.\n`);

process.exitCode = findings === 0 ? 0 : 1;
